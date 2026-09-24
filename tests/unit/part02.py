"""Part 2 of the unit suite. Imported for its side effects."""
from unit.part01 import (NS, SO, _privmod, _sm_core, _sm_cron, _sm_files, _sm_firewall, _sm_game, _sm_gmod, _sm_hosts, can_access_remote, check, client_ip, config, eq, os)  # noqa: F401,E402


# ── local-host injection defenses: system_ops runs commands on THIS machine (shell=True), so its
#    request-fed values (block/unban IPs, jail names) must be neutralised before reaching _run. ──
#
# _run_verb is stubbed as well as _run, and that is the whole point. _run_verb has THREE branches:
# the helper when it is installed, the tool directly when already root, and the pre-helper shell
# form otherwise — and only the third goes through _run. So stubbing _run alone leaves the first
# two live: on a machine with the helper installed (i.e. any properly installed panel host) these
# checks reached the REAL boundary. Running this suite as `ubuntu` on the test VPS wrote two real
# `ufw deny` rules, for 10.0.0.5 and 10.0.0.6, to a live firewall — from a suite whose own header
# in run-tests.sh calls it "pure logic; no network". It passed on dev machines and in CI only
# because neither has the helper, so the fallback branch was taken and the stub caught it.
#
# The replacement routes through the same shell-form builder the fallback would have used, so every
# assertion below is unchanged and no branch can escape to the real host.
_orig_so_run, _orig_so_verb = SO._run, SO._run_verb
try:
    _so = []
    SO._run = lambda cmd, *a, **k: (_so.append(cmd), ("", "", 0))[1]
    SO._run_verb = lambda v, a=(), timeout=30, merge_stderr=True: (
        _so.append(_privmod.remote_command(v, a, merge_stderr=merge_stderr)), ("", "", 0))[1]

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
    # ...and the RESULT is read. This discarded the tuple and returned True unconditionally,
    # while ufw_deny_ip right above it fails on a non-zero rc. So a timeout, a missing helper
    # binary or a sudo refusal all answered "Unblocked", turned the toast green, and wrote an
    # audit row recording a successful unblock — for a deny rule still sitting in the firewall.
    _so.clear()
    SO._run_verb = lambda v, a=(), timeout=30, merge_stderr=True: ("", "Command timed out", -1)
    _ok, _msg = SO.ufw_undeny_ip("10.0.0.7")
    check("ufw_undeny_ip: a command that FAILED is not reported as an unblock",
          _ok is False, "returned %r / %r" % (_ok, _msg))
    check("ufw_undeny_ip: ...and says what went wrong", "timed out" in (_msg or ""), _msg)
    SO._run_verb = lambda v, a=(), timeout=30, merge_stderr=True: ("", "", 0)
    _ok, _ = SO.ufw_undeny_ip("10.0.0.7")
    check("ufw_undeny_ip: ...while a clean run still reports success", _ok is True)
finally:
    SO._run, SO._run_verb = _orig_so_run, _orig_so_verb

# ── fail2ban_unban: jail must be metacharacter-free AND on the host's real jail allowlist;
#    IP is canonicalised through ipaddress. Both are shlex-quoted at the sink. ──
# _run_verb stubbed here too — same reason as the ufw block above: without it, a host with the
# helper installed runs `fail2ban-client set <jail> unbanip <ip>` for real.
_orig_so_run2, _orig_jails, _orig_so_verb2 = SO._run, SO._fail2ban_jails, SO._run_verb
try:
    _fb = []
    SO._run = lambda cmd, *a, **k: (_fb.append(cmd), ("", "", 0))[1]
    SO._run_verb = lambda v, a=(), timeout=30, merge_stderr=True: (
        _fb.append(_privmod.remote_command(v, a, merge_stderr=merge_stderr)), ("", "", 0))[1]
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
    SO._run, SO._fail2ban_jails, SO._run_verb = _orig_so_run2, _orig_jails, _orig_so_verb2

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
# Every stub below ends its output with _BACKUP_LIST_DONE, because that is what a SUCCESSFUL read
# looks like: the listing prints the sentinel last so a run cut short is not mistaken for "no
# backups" (the command ends in a pipeline through `head`, which exits 0 whatever failed before
# it). A stub that models success has to model all of it — without the sentinel these three were
# modelling a FAILED read while asserting the parse of a good one, and when the sentinel check
# went in they started returning None and `len(None)` took the whole module down at import.
_BK_END = "\n%s\n" % _sm_cron._BACKUP_LIST_DONE
_orig_run7 = _sm_core.run_command
try:
    _sm_core.run_command = lambda s, c, **k: (
        "F\tgmodserver-2026.tar.gz\t1048576\t1720000000\nF\told.tar.gz\t500\t1719000000" + _BK_END, "", 0)
    _gbl = _sm_cron.list_game_backups(None, "gm")
    check("game backups: parsed newest-first with sizes",
          len(_gbl) == 2 and _gbl[0]["name"] == "gmodserver-2026.tar.gz" and _gbl[0]["size"] == 1048576)
    check("game backups: no lock -> nothing marked in-progress",
          not any(b.get("in_progress") for b in _gbl))
    # Lock present + a NEW archive written after the backup started (lock mtime 1720000050) -> that
    # new one is in-progress; the pre-existing older backup is not.
    _sm_core.run_command = lambda s, c, **k: (
        "F\tgmodserver-new.tar.zst\t2000\t1720000100\nF\tgmodserver-old.tar.zst\t1048576\t1720000000\n"
        "LOCK\t1720000050.5" + _BK_END, "", 0)
    _gbl2 = _sm_cron.list_game_backups(None, "gm")
    check("game backups: active lock flags the new archive in-progress only",
          _gbl2[0]["name"] == "gmodserver-new.tar.zst" and _gbl2[0].get("in_progress") is True
          and not _gbl2[1].get("in_progress"))
    # Early in a backup (lock present, new archive not created yet): the existing backup predates the
    # lock, so it must NOT be flagged/hidden — this is the "existing backup disappears" regression.
    _sm_core.run_command = lambda s, c, **k: (
        "F\tgmodserver-old.tar.zst\t1048576\t1720000000\nLOCK\t1720000050.5" + _BK_END, "", 0)
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
            # {c, ok}, the shape player_count asks jq for now: a bare number could not tell a
            # real answer from gamedig's {"error":...}, whose .players is null and whose
            # `length` jq reports as 0.
            return ('{"c":2,"ok":true}', "", 0)
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
    # ── the per-server query_type override reaches the guard ──────────────────────────────────
    # run_game_backup had no query_type parameter at all, so player_count's fourth argument was
    # always None and the gamedig type came from the 26-entry built-in map ALONE. A game the map
    # does not cover — Project Zomboid, ARK, Mordhau, Killing Floor — whose operator set the
    # override precisely so the panel could query it resolved to "", player_count answered None,
    # and this function's documented rule reads None as empty: the hourly ticker ran LinuxGSM's
    # `backup`, which STOPS the server, and disconnected everyone on it. Every other player and
    # version read in game.py threads the override; only the one that decides whether to
    # disconnect people did not.
    _cap_busy["cmds"] = []
    _qok, _qmsg, _qskip = _sm_game.run_game_backup(None, "gm", "zomboidserver", 2,
                                                   game_type="pzomboid", port=16261,
                                                   query_type="projectzomboid")
    _q_joined = " ".join(_cap_busy["cmds"])
    check("run_game_backup: an unmapped game's query_type override reaches the players guard",
          "--type projectzomboid" in _q_joined,
          "gamedig was called as %r" % (_q_joined[:200],))
    check("run_game_backup: ...so 2 players online skips the backup on that server too",
          _qok is False and _qskip is True and "./zomboidserver backup" not in _q_joined,
          str((_qok, _qmsg, _qskip)))
    # Positive control: the same unmapped game with NO override is still unqueryable, so the
    # documented "unknown counts as empty" rule still lets it back up on schedule.
    _cap_busy["cmds"] = []
    _nok, _nmsg, _nskip = _sm_game.run_game_backup(None, "gm", "zomboidserver", 2,
                                                   game_type="pzomboid", port=16261)
    check("run_game_backup: ...while an unmapped game with no override still backs up (unknown)",
          _nok is True and _nskip is False
          and "./zomboidserver backup" in " ".join(_cap_busy["cmds"]),
          str((_nok, _nmsg, _nskip)))
finally:
    _sm_core.run_command = _orig_run8b

# ── empty/unqueryable server: player_count None, backup proceeds ──
_orig_run8c = _sm_core.run_command
try:
    _sm_core.run_command = lambda s, c, **k: (('{"c":0,"ok":true}', "", 0) if "gamedig" in c
                                              else ("", "", 0))
    check("player_count: 0 players -> 0", _sm_cron.player_count(None, "gm", "gmod", 27015) == 0)
    check("player_count: unmapped game -> None (unknown)", _sm_cron.player_count(None, "gm", "nosuchgame", 27015) is None)
    check("player_count: no port -> None", _sm_cron.player_count(None, "gm", "gmod", None) is None)
    _eok, _emsg, _eskip = _sm_game.run_game_backup(None, "gm", "gmodserver", 2, game_type="gmod", port=27015)
    check("run_game_backup: empty server backs up normally", _eok is True and _eskip is False)
finally:
    _sm_core.run_command = _orig_run8c

# ── player_count_via_lgsm_query: the THIRD reader in this file to need the `ok` guard ──────────
# It covers games absent from the 26-entry GAMEDIG_TYPE map by using LinuxGSM's own querytype, and
# it fed the reboot-when-empty poller (monitoring._host_idle_state -> _reboot_when_empty_watch).
# It asked jq for a bare `.players|length`; gamedig writes its failure to stdout as
# {"error":"Failed all 1 attempts"}, `.players` is then null, and jq reports the length of null as
# 0 (measured: `echo '{"error":"x"}' | jq -r '.players|length'` prints 0, rc 0). So a dropped query
# on a server with ten people on it returned a confident 0 and the host was rebooted under them —
# while the function's own docstring promised None for "the query fails".
_orig_lgv_q, _orig_run_q = _sm_files.lgsm_get_values, _sm_core.run_command
try:
    _sm_files.lgsm_get_values = lambda *a, **k: {"querymode": "2", "querytype": "protocol-valve",
                                                 "queryport": "27015", "port": "27015"}
    _cap_q = {}
    def _q_run(_s, c, **k):
        """Model the real pipeline, not one function's output.

        Feeding this check a fixed '{"c":0,"ok":false}' would make it pass on the BROKEN code
        too — the bare parser sees a non-decimal string and also answers None, for the wrong
        reason. So answer as jq really would, for the document gamedig really emits when a query
        fails ({"error":"Failed all 1 attempts"}): the guarded filter yields ok:false, and the
        bare `.players|length` yields 0, because jq reports the length of null as 0."""
        _cap_q["cmd"] = c
        if 'type=="array"' in c:
            return ('{"c":0,"ok":false}', "", 0)
        return ("0", "", 0)
    _sm_core.run_command = _q_run
    check("player_count_via_lgsm_query: a failed gamedig query is None, NOT 0",
          _sm_cron.player_count_via_lgsm_query(None, "gm", "gmodserver") is None)
    check("player_count_via_lgsm_query: asks jq whether .players is really an array",
          'type=="array"' in _cap_q.get("cmd", ""), _cap_q.get("cmd", "")[:200])
    _sm_core.run_command = lambda s, c, **k: ('{"c":0,"ok":true}', "", 0)
    check("player_count_via_lgsm_query: a genuinely empty server is still 0",
          _sm_cron.player_count_via_lgsm_query(None, "gm", "gmodserver") == 0)
    _sm_core.run_command = lambda s, c, **k: ('{"c":7,"ok":true}', "", 0)
    check("player_count_via_lgsm_query: a real count is returned",
          _sm_cron.player_count_via_lgsm_query(None, "gm", "gmodserver") == 7)
    # ...and an unreadable CONFIG is unknown too, rather than falling through as "no query".
    _sm_files.lgsm_get_values = lambda *a, **k: None
    check("player_count_via_lgsm_query: an unreadable LinuxGSM config is None",
          _sm_cron.player_count_via_lgsm_query(None, "gm", "gmodserver") is None)
finally:
    _sm_files.lgsm_get_values, _sm_core.run_command = _orig_lgv_q, _orig_run_q

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
    # The trailing sentinel is part of the contract now: the command prints it after the three
    # cats, so its ABSENCE means the read never finished. See the None checks below.
    _sm_core.run_command = lambda s, c, **k: (
        'discordalert="off"\ndiscordwebhook="default"\nemailalert="on"\n'
        'discordalert="on"\ndiscordwebhook="https://x/hook"\n' + _sm_files._READ_END, "", 0)
    _av = _sm_files.lgsm_get_values(None, "gm", "gmodserver",
                             ["discordalert", "discordwebhook", "emailalert", "missingkey"])
    check("lgsm_get_values: later (instance) value wins",
          _av["discordwebhook"] == "https://x/hook" and _av["discordalert"] == "on")
    check("lgsm_get_values: reads other toggles; missing key -> empty",
          _av["emailalert"] == "on" and _av["missingkey"] == "")

    # ── a read that did not happen is None, not a dict of "" ────────────────────────────────
    # The Alerts card paints these values into inputs and Save posts them all back, so a
    # confident {"discordtoken": ""} for an unreadable host wiped real credentials on the next
    # Save. run_command does NOT raise on the tailscale/local transports — it returns
    # ("", "...timed out", -1) — so this is the shape the common deployment actually produces.
    _sm_core.run_command = lambda s, c, **k: ("", "SSH command timed out", -1)
    check("lgsm_get_values: a timed-out read is None, not every-key-empty",
          _sm_files.lgsm_get_values(None, "gm", "gmodserver", ["discordalert", "discordtoken"]) is None)
    # ...and a partial read (transport died mid-stream) is equally not a measurement.
    _sm_core.run_command = lambda s, c, **k: ('discordalert="on"\ndiscordtoken="secr', "", 0)
    check("lgsm_get_values: an unframed (truncated) read is None",
          _sm_files.lgsm_get_values(None, "gm", "gmodserver", ["discordalert"]) is None)
    # ...while three legitimately-absent cfg files ARE a measurement: empty, but read.
    _sm_core.run_command = lambda s, c, **k: (_sm_files._READ_END, "", 0)
    _fresh = _sm_files.lgsm_get_values(None, "gm", "gmodserver", ["discordalert"])
    check("lgsm_get_values: a fresh instance with no cfg yet reads as empty, not unreadable",
          _fresh == {"discordalert": ""}, repr(_fresh))
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

    # ── "could not read the firewall" is a THIRD answer, not "tailnet-only" ───────────────────
    # remote_public_ssh_status discarded the rc, so an unreadable host produced out="" ->
    # active=False, mode="off", which the UI states as "public SSH is disabled — tailnet only".
    # That is the reassurance an operator acts on before closing port 22. The non-raising
    # transports make it the common failure: run_command returns ("", "...timed out", -1).
    _sm_core.run_privileged = lambda s, v, a=(), **k: ("", "SSH command timed out", -1)
    _st = _sm_hosts.remote_public_ssh_status(object())
    check("public ssh: an unreadable firewall is 'unknown', never 'off'",
          _st.get("unreachable") is True and _st.get("mode") != "off", str(_st))
    _ok, _msg = _sm_hosts.remote_set_public_ssh(object(), "limit")
    check("public ssh: ...and setting it then says the state is unknown, not 'UFW is not active'",
          _ok is False and "unknown" in _msg.lower(), str(_msg))
    # ufw ABSENT is a reading, not a failed read — it keeps its own answer, and it is still not
    # "off", because with no firewall nothing governs port 22 at all.
    _sm_core.run_privileged = lambda s, v, a=(), **k: ("", "ufw: command not found", 127)
    _st = _sm_hosts.remote_public_ssh_status(object())
    check("public ssh: an absent ufw is reported as not-installed, not as unreachable",
          _st.get("installed") is False and not _st.get("unreachable")
          and _st.get("mode") != "off", str(_st))
    # positive control: a real read still answers with a real mode.
    _ufw_says("limit")
    _st = _sm_hosts.remote_public_ssh_status(object())
    check("public ssh: a readable firewall still reports its actual mode (positive control)",
          _st.get("mode") == "limit" and not _st.get("unreachable"), str(_st))
    # ufw translates its Status line WHOLE (fr.po: `État : actif`); the rules listing is not. A
    # literal "Status:" gate read such a host as unreachable before the locale-aware reading ran.
    _FR_UFW = ("État : actif\n\n"
               "Vers                       Action      De\n"
               "----                       ------      --\n")
    _sm_core.run_privileged = lambda s, v, a=(), **k: (
        _FR_UFW + "22/tcp                     LIMIT IN    Anywhere\n", "", 0)
    _st = _sm_hosts.remote_public_ssh_status(object())
    check("public ssh: a host whose ufw prints a translated Status line is read, not 'unreachable'",
          _st.get("mode") == "limit" and _st.get("active") is True and not _st.get("unreachable"),
          str(_st))
    _sm_core.run_privileged = lambda s, v, a=(), **k: ("", "", 0)
    _st = _sm_hosts.remote_public_ssh_status(object())
    check("public ssh: ...while an EMPTY answer with rc 0 is still unreadable, never 'off'",
          _st.get("unreachable") is True and _st.get("mode") != "off", str(_st))

    # ── ufw stops at the FIRST rule a connection matches ─────────────────────────────────────
    # Any LIMIT line used to win, so `OpenSSH ALLOW` above `22/tcp LIMIT` — what `ufw allow
    # OpenSSH` plus the Limit button produce — read as rate-limited while every connection matched
    # the ALLOW first. And 'limit' deleted only `allow 22/tcp`: to ufw the OpenSSH profile and a
    # bare `22` are different rules, so both stayed ahead of the appended limit.
    def _ufw_status_is(text):
        _sm_core.run_privileged = lambda s, v, a=(), **k: (text, "", 0)
        return _sm_hosts.remote_public_ssh_status(object()).get("mode")
    _hdr = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n"
    check("public ssh: an ALLOW listed ahead of the LIMIT is what SSH gets",
          _ufw_status_is(_hdr + "OpenSSH                    ALLOW IN    Anywhere\n"
                                "22/tcp                     LIMIT IN    Anywhere\n") == "allow",
          "reported rate-limited while every connection matches the OpenSSH ALLOW above it")
    check("public ssh: ...and a LIMIT listed first is still limit (positive control)",
          _ufw_status_is(_hdr + "22/tcp                     LIMIT IN    Anywhere\n"
                                "OpenSSH                    ALLOW IN    Anywhere\n") == "limit")
    check("public ssh: ...and an allow for ONE source address does not decide the public mode",
          _ufw_status_is(_hdr + "22/tcp                     ALLOW IN    203.0.113.5\n"
                                "22/tcp                     LIMIT IN    Anywhere\n") == "limit",
          "`allow from <home ip> to 22` (this panel's own Restrict box) read as public SSH open")

    def _fake_ufw(rules):
        """A firewall that applies the verbs with ufw's own semantics: a rule that differs only in
        action is rewritten IN PLACE, a new one is appended, and a delete removes only an exact
        (To, action) match — the OpenSSH profile and a bare 22 are not `22/tcp`."""
        def _rp(s, v, a=(), **k):
            a = list(a)
            if v == "ufw-status":
                return (_hdr + "".join("%-26s %-11s Anywhere\n" % (t, act + " IN") for t, act in rules), "", 0)
            want = {"ufw-limit-port": "LIMIT", "ufw-allow-port": "ALLOW"}.get(v)
            if want:
                for i, (t, _act) in enumerate(rules):
                    if t == a[0]:
                        rules[i] = (t, want)
                        return ("Rule updated", "", 0)
                rules.append((a[0], want))
                return ("Rule added", "", 0)
            gone = {"ufw-delete-allow-port": "ALLOW", "ufw-delete-limit-port": "LIMIT",
                    "ufw-delete-allow-app": "ALLOW"}.get(v)
            if gone and (a[0], gone) in rules:
                rules.remove((a[0], gone))
                return ("Rule deleted", "", 0)
            return ("Could not delete non-existent rule", "", 1)
        _sm_core.run_privileged = _rp
    for _start in (["OpenSSH"], ["22"]):
        _rules = [(_t, "ALLOW") for _t in _start]
        _fake_ufw(_rules)
        _ok, _msg = _sm_hosts.remote_set_public_ssh(object(), "limit")
        check("public ssh: 'limit' on a host opened with `ufw allow %s` is really limited" % _start[0],
              _ok is True and _rules and _rules[0] == ("22/tcp", "LIMIT"),
              "ok=%r msg=%r rules now %r" % (_ok, _msg, _rules))
    _rules = [("22/tcp", "ALLOW")]
    _fake_ufw(_rules)
    _ok, _msg = _sm_hosts.remote_set_public_ssh(object(), "limit")
    check("public ssh: ...and an existing 22/tcp allow is turned into the limit (positive control)",
          _ok is True and _rules == [("22/tcp", "LIMIT")], "ok=%r rules %r" % (_ok, _rules))
    # ...and the new rule is the GATE for those deletes. The loop ignored every exit code, so when
    # `ufw limit 22/tcp` failed (a timeout, a held lock) it deleted `allow OpenSSH` anyway and a host
    # opened only by it had nothing left letting SSH in; 'allow' likewise deleted the LIMIT. The
    # two cases above, where the add works, are the positive control.
    for _mode_g, _add_g, _start_g in (("limit", "ufw-limit-port", [("OpenSSH", "ALLOW")]),
                                      ("allow", "ufw-allow-port", [("22/tcp", "LIMIT")])):
        _rules = list(_start_g)
        _fake_ufw(_rules)
        _sm_core.run_privileged = (lambda s, v, a=(), _i=_sm_core.run_privileged, _add=_add_g, **k:
                                   ("", "ERROR: Could not acquire lock", 1) if v == _add
                                   else _i(s, v, a, **k))
        _ok, _msg = _sm_hosts.remote_set_public_ssh(object(), _mode_g)
        check("public ssh: '%s' whose new 22/tcp rule fails removes no rule that lets SSH in" % _mode_g,
              _ok is False and _rules == _start_g and "Could not acquire lock" in _msg,
              "ok=%r msg=%r rules now %r" % (_ok, _msg, _rules))

    # ── rate limiting a port the panel itself opened ─────────────────────────────────────────
    # Every game port is opened BARE (`ufw allow 28016 comment rustserver`, tcp+udp). The limit
    # path deleted only `allow proto tcp port 28016`, which ufw does not match against a bare rule,
    # so the limit was appended after the ALLOW and the answer was "28016/tcp is now rate limited".
    def _fake_ufw_n(rules):
        """Numbered listing, comments included; same in-place/append/exact-delete semantics."""
        def _rp(s, v, a=(), **k):
            a = list(a)
            if v == "ufw-status":
                return ("Status: active\n\n     To                         Action      From\n"
                        "     --                         ------      ----\n"
                        + "".join("[%2d] %-26s %-11s Anywhere%s\n"
                                  % (i + 1, r[0], r[1] + " IN", (" # " + r[2]) if r[2] else "")
                                  for i, r in enumerate(rules)), "", 0)
            want = {"ufw-limit-port": "LIMIT", "ufw-allow-port": "ALLOW"}.get(v)
            if want:
                for i, r in enumerate(rules):
                    if r[0] == a[0]:
                        rules[i] = (r[0], want, a[1] if len(a) > 1 else "")
                        return ("Rule updated", "", 0)
                rules.append((a[0], want, a[1] if len(a) > 1 else ""))
                return ("Rule added", "", 0)
            if v in ("ufw-delete-allow-port", "ufw-delete-limit-port"):
                act = "ALLOW" if v == "ufw-delete-allow-port" else "LIMIT"
                hit = [r for r in rules if r[0] == a[0] and r[1] == act]
                for r in hit:
                    rules.remove(r)
                return (("Rule deleted", "", 0) if hit else ("Could not delete non-existent rule", "", 1))
            return ("", "", 0)
        _sm_core.run_privileged = _rp

    def _first_for(rules, spec, proto):
        """What a `proto` connection to `spec` meets first, as ufw evaluates it."""
        for r in rules:
            if r[0] in (spec, "%s/%s" % (spec, proto)):
                return r[1]
        return None
    _rules = [("28016", "ALLOW", "rustserver")]
    _fake_ufw_n(_rules)
    _ok, _msg = _sm_hosts.remote_ufw_limit_port(object(), 28016, "tcp", limit=True)
    check("ufw limit: a port opened bare (tcp+udp) is really limited for tcp",
          _ok is True and _first_for(_rules, "28016", "tcp") == "LIMIT",
          "ok=%r msg=%r rules %r — the bare ALLOW still meets every connection first"
          % (_ok, _msg, _rules))
    check("ufw limit: ...and its udp half stays open, under the same comment",
          _first_for(_rules, "28016", "udp") == "ALLOW" and ("28016/udp", "ALLOW", "rustserver") in _rules,
          "rules %r" % (_rules,))
    _ok, _msg = _sm_hosts.remote_ufw_limit_port(object(), 28016, "tcp", limit=False)
    check("ufw limit: removing the limit leaves the port open, un-throttled",
          _ok is True and _first_for(_rules, "28016", "tcp") == "ALLOW", "ok=%r rules %r" % (_ok, _rules))
    _ok, _msg = _sm_hosts.remote_ufw_limit_port(object(), 28017, "tcp", limit=False)
    check("ufw limit: ...and 'remove' on a port with no limit opens nothing",
          _ok is False and not any(r[0].startswith("28017") for r in _rules), "ok=%r rules %r" % (_ok, _rules))
    check("ufw limit: ...saying it has no rate limit (positive control for the inactive case below)",
          "no rate limit" in _msg, "msg=%r" % (_msg,))
    # An INACTIVE ufw lists no rules at all, stored ones included, so the same test answered
    # "22/tcp has no rate limit to remove" about a host whose stored rules hold one.
    _inact_ran = []
    _sm_core.run_privileged = lambda s, v, a=(), **k: (
        ("Status: inactive\n", "", 0) if v == "ufw-status" else (_inact_ran.append(v), ("", "", 0))[1])
    _ok, _msg = _sm_hosts.remote_ufw_limit_port(object(), 22, "tcp", limit=False)
    check("ufw limit: removing a limit on an INACTIVE ufw says it cannot read the rules, not 'no limit'",
          _ok is False and "not active" in _msg and "no rate limit" not in _msg and not _inact_ran,
          "ok=%r msg=%r ran %r" % (_ok, _msg, _inact_ran))
    _rules = [("28000:28100/tcp", "ALLOW", "")]
    _fake_ufw_n(_rules)
    _ok, _msg = _sm_hosts.remote_ufw_limit_port(object(), 28016, "tcp", limit=True)
    check("ufw limit: a rule it cannot remove that still matches first is reported, not hidden",
          _ok is False and "28000:28100/tcp" in _msg, "ok=%r msg=%r" % (_ok, _msg))
    _rules = []
    _fake_ufw_n(_rules)
    _ok, _msg = _sm_hosts.remote_ufw_limit_port(object(), 28016, "tcp", limit=True)
    check("ufw limit: ...while a port with nothing ahead of it is limited (positive control)",
          _ok is True and _rules == [("28016/tcp", "LIMIT", "")], "ok=%r msg=%r rules %r" % (_ok, _msg, _rules))
    # The bare rule goes only once the other protocol is re-opened on its own. The re-allow's exit
    # code was ignored: when it failed, 28016/udp — gameplay — was closed, and the answer was "now
    # rate limited", the read-back looking at tcp only. (The split above is the positive control.)
    _rules = [("28016", "ALLOW", "rustserver")]
    _fake_ufw_n(_rules)
    _sm_core.run_privileged = (lambda s, v, a=(), _i=_sm_core.run_privileged, **k:
                               ("", "ERROR: timed out", 1) if (v, list(a)[:1]) == ("ufw-allow-port", ["28016/udp"])
                               else _i(s, v, a, **k))
    _ok, _msg = _sm_hosts.remote_ufw_limit_port(object(), 28016, "tcp", limit=True)
    check("ufw limit: a failed re-allow of the other protocol leaves the bare rule, and says so",
          _ok is False and ("28016", "ALLOW", "rustserver") in _rules and "28016/udp" in _msg,
          "ok=%r msg=%r rules %r" % (_ok, _msg, _rules))
    # ...but the read-back, not the failed re-allow, decides: where the limit rewrote a 28016/tcp
    # allow ABOVE the bare rule, it is what tcp meets first, and udp is still open through the bare.
    _rules = [("28016/tcp", "ALLOW", ""), ("28016", "ALLOW", "rustserver")]
    _fake_ufw_n(_rules)
    _sm_core.run_privileged = (lambda s, v, a=(), _i=_sm_core.run_privileged, **k:
                               ("", "ERROR: timed out", 1) if (v, list(a)[:1]) == ("ufw-allow-port", ["28016/udp"])
                               else _i(s, v, a, **k))
    _ok, _msg = _sm_hosts.remote_ufw_limit_port(object(), 28016, "tcp", limit=True)
    check("ufw limit: ...while a limit already ahead of the bare rule is limited, udp left open",
          _ok is True and _rules == [("28016/tcp", "LIMIT", ""), ("28016", "ALLOW", "rustserver")],
          "ok=%r msg=%r rules %r" % (_ok, _msg, _rules))
    # ...and a re-allow that "worked" without the rule appearing is caught by the read-back.
    _rules = [("28016", "ALLOW", "rustserver")]
    _fake_ufw_n(_rules)
    _sm_core.run_privileged = (lambda s, v, a=(), _i=_sm_core.run_privileged, **k:
                               ("Skipping", "", 0) if (v, list(a)[:1]) == ("ufw-allow-port", ["28016/udp"])
                               else _i(s, v, a, **k))
    _ok, _msg = _sm_hosts.remote_ufw_limit_port(object(), 28016, "tcp", limit=True)
    check("ufw limit: ...and a split that closed the other protocol anyway is reported, not 'limited'",
          _ok is False and _first_for(_rules, "28016", "udp") is None and "28016/udp" in _msg,
          "ok=%r msg=%r rules %r" % (_ok, _msg, _rules))
    # The read-back required the literal "Status:" line, which ufw translates whole: on a French
    # host a limit that fully applied, bare rule split and all, came back "could not be read back".
    _rules = [("28016", "ALLOW", "rustserver")]
    _fake_ufw_n(_rules)
    _sm_core.run_privileged = (lambda s, v, a=(), _i=_sm_core.run_privileged, **k:
                               (lambda r: (r[0].replace("Status: active", "État : actif"),) + r[1:])(
                                   _i(s, v, a, **k)))
    _ok, _msg = _sm_hosts.remote_ufw_limit_port(object(), 28016, "tcp", limit=True)
    check("ufw limit: a host whose ufw prints a translated Status line is read back, not 'unread'",
          _ok is True and _first_for(_rules, "28016", "tcp") == "LIMIT", "ok=%r msg=%r" % (_ok, _msg))
    _sm_core.run_privileged = lambda s, v, a=(), **k: ("", "", 0)
    _ok, _msg = _sm_hosts.remote_ufw_limit_port(object(), 28016, "tcp", limit=True)
    check("ufw limit: ...while an EMPTY read-back is still 'could not be read back' (positive control)",
          _ok is False and "read back" in _msg, "ok=%r msg=%r" % (_ok, _msg))

    # ── the unblock that always said it worked ───────────────────────────────────────────────
    # remote_ufw_undeny_ip discarded the verb's result and returned True unconditionally, while
    # remote_ufw_deny_ip six lines above it checks rc. Its LOCAL twin (system_ops.ufw_undeny_ip)
    # was fixed for exactly this and carries the comment; the remote one was missed. The caller
    # that matters is monitoring._autoblock_reconcile, which tallies releases from this value.
    _sm_core.run_privileged = lambda s, v, a=(), **k: ("", "Command timed out", -1)
    _ok, _msg = _sm_hosts.remote_ufw_undeny_ip(object(), "203.0.113.9")
    check("ufw unblock: a delete that failed is not reported as 'Unblocked'",
          _ok is False, str(_msg))
    _sm_core.run_privileged = lambda s, v, a=(), **k: ("", "", 0)
    _ok, _msg = _sm_hosts.remote_ufw_undeny_ip(object(), "203.0.113.9")
    check("ufw unblock: a delete that worked still reports success (positive control)",
          _ok is True and "203.0.113.9" in _msg, str(_msg))
    check("ufw unblock: an invalid IP is still refused before any command runs",
          _sm_hosts.remote_ufw_undeny_ip(object(), "not-an-ip")[0] is False)

    # ── reboot: a refusal is knowable even though success is not ─────────────────────────────
    # A reboot's success looks like a failure (the host goes down mid-command), so this cannot
    # simply fail on non-zero. But a REFUSAL answers promptly and positively — sudo declining, an
    # unknown verb, no helper — while -1 is the transport giving up. Both callers use the boolean,
    # and monitoring writes it as `success=` on the audit row.
    _sm_core.run_privileged = lambda s, v, a=(), **k: ("", "sudo: a password is required", 1)
    _ok, _msg = _sm_hosts.remote_reboot(object())
    check("reboot: a refused reboot is reported as refused", _ok is False, str(_msg))
    _sm_core.run_privileged = lambda s, v, a=(), **k: ("", "SSH command timed out", -1)
    check("reboot: ...but a dropped connection still counts as sent, which is what a reboot IS",
          _sm_hosts.remote_reboot(object())[0] is True)
    _sm_core.run_privileged = lambda s, v, a=(), **k: ("", "", 0)
    check("reboot: ...and a clean send is sent (positive control)",
          _sm_hosts.remote_reboot(object())[0] is True)
finally:
    # BOTH, not just run_command. This block stubs run_privileged too (saved as _orig_rp above)
    # and never put it back, so every later check in this flat script ran against the last stub
    # set here — the leak tests/unit_test.py's own header warns about.
    _sm_core.run_command, _sm_core.run_privileged = _orig_rc, _orig_rp
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
# The page deletes by rule NUMBER, and numbers are positions: the hourly auto-block inserts a deny
# at 1 and every rule below moves down. A group's `key` is what the page re-finds it by before
# each delete, so it must survive a renumbering and tell rules apart.
_shifted = _sm_firewall._group_ufw_rules(_rules([
    "Anywhere  DENY IN  203.0.113.9  # panel-autoblock",
    "22/tcp  ALLOW IN  Anywhere",
    "22/tcp (v6)  ALLOW IN  Anywhere (v6)",
    "5000/tcp  ALLOW IN  Anywhere",
    "28960  ALLOW IN  Anywhere  # codserver",
    "27015/udp  ALLOW IN  Anywhere",
]))
_shifted_by = {g["port_num"]: g for g in _shifted}
check("ufw grouping: a group's key survives the renumbering an inserted deny causes",
      all(g.get("key") and g.get("key") == _shifted_by[p].get("key")
          and g["nums"] != _shifted_by[p]["nums"] for p, g in by_port.items()),
      "%r vs %r" % ([g.get("key") for g in groups], [g.get("key") for g in _shifted]))
check("ufw grouping: ...and no two groups share one (positive control)",
      len({g.get("key") for g in _shifted}) == len(_shifted) and all(g.get("key") for g in _shifted),
      repr([g.get("key") for g in _shifted]))

# ── firewall lock-out protection ──────────────────────────────
def protect(server, rules, enabled=True, cfg=None, is_local=False, tailscale=(False, False),
            cfg_unreadable=None):
    # Restores what it replaces. It used to leave sm.is_local_server stubbed for the REST of the
    # suite — every later test saw whatever the last protect() call happened to pass, which is how
    # a stub stops being scaffolding and starts being a silent global. Nothing depended on the leak
    # (this fix changed no other result), but the transport tests further down do read the real
    # is_local_server, and would have been testing the wrong branch.
    _saved = (_sm_core.is_local_server, _sm_hosts._tailscale_conn_state, config.load_config,
              _sm_firewall._config_unreadable)
    try:
        _sm_core.is_local_server = lambda s: is_local
        _sm_hosts._tailscale_conn_state = lambda s: tailscale   # (running, ssh_enabled) — deterministic
        if cfg is not None:
            config.load_config = lambda: cfg
            # config.json is consulted TWICE now: through load_config, and RAW by
            # _config_unreadable. Stubbing only the first would leave these checks reading
            # whatever data/config.json happens to hold on the machine running the suite — a
            # corrupt one there would silently change what every case below is testing.
            _sm_firewall._config_unreadable = lambda: False
        if cfg_unreadable is not None:
            _sm_firewall._config_unreadable = lambda: cfg_unreadable
        return _sm_firewall._annotate_firewall_protection(server, enabled, _sm_firewall._group_ufw_rules(_rules(rules)))
    finally:
        (_sm_core.is_local_server, _sm_hosts._tailscale_conn_state, config.load_config,
         _sm_firewall._config_unreadable) = _saved


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

# Once Tailscale Serve is configured AND the tailnet is actually up, the panel IS reachable over
# the tailnet -> the public port is no longer the only way in -> NOT protected.
g = protect(NS(port=22), ["22/tcp ALLOW IN Anywhere", "5000/tcp ALLOW IN Anywhere",
                          "Anywhere ALLOW IN Anywhere on tailscale0"],
            cfg={"port": 5000, "tailscale_setup_done": True}, is_local=True,
            tailscale=(True, True))
gp = {x["port_num"]: x for x in g}
check("local + Serve set up and the tailnet UP: panel 5000 NOT protected",
      not gp["5000"]["protected"])

# ...but `tailscale_setup_done` on its own is a STORED FLAG, not a statement about the tailnet
# being up now. tailscaled can be stopped or logged out and node keys expire, and this function
# already refuses to trust a stale tailscale0 RULE for the same reason. Trusting the flag alone
# un-protected the only remaining route to the panel UI, so the Firewall page offered a plain
# delete on it.
g = protect(NS(port=22), ["22/tcp ALLOW IN Anywhere", "5000/tcp ALLOW IN Anywhere",
                          "Anywhere ALLOW IN Anywhere on tailscale0"],
            cfg={"port": 5000, "tailscale_setup_done": True}, is_local=True,
            tailscale=(False, False))
gp = {x["port_num"]: x for x in g}
check("local + Serve flag set but the tailnet DOWN: panel 5000 stays protected",
      gp["5000"]["protected"],
      "a stale tailscale_setup_done must not un-protect the only way into the panel")
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

# `tailscale_setup_done` records that Serve was configured ONCE — it is not a statement about the
# tailnet being up now. tailscaled can be stopped or logged out and node keys expire by default,
# and nothing writes the flag back. With the flag stale and Tailscale down, the panel host's own
# web-port rule came back is_panel=False, protected=False AND warn=False: the UI drew an ordinary
# red × with no confirmation text on the only remaining route into the panel. The same live
# reading the tailscale0 rule already insists on decides this one now.
g = protect(NS(port=22), ["22/tcp ALLOW IN Anywhere", "5000/tcp ALLOW IN Anywhere",
                          "Anywhere ALLOW IN Anywhere on tailscale0"],
            cfg={"port": 5000, "tailscale_setup_done": True}, is_local=True, tailscale=(False, False))
gp = {x["port_num"]: x for x in g}
check("panel port: Serve configured but Tailscale DOWN still protects the panel's web port",
      gp["5000"]["is_panel"] and gp["5000"]["protected"],
      "is_panel=%s protected=%s" % (gp["5000"]["is_panel"], gp["5000"]["protected"]))
# Positive control: with the tailnet actually up, Serve really is another way in, so the public
# port goes back to being closeable — which is the whole point of the flag.
g = protect(NS(port=22), ["22/tcp ALLOW IN Anywhere", "5000/tcp ALLOW IN Anywhere",
                          "Anywhere ALLOW IN Anywhere on tailscale0"],
            cfg={"port": 5000, "tailscale_setup_done": True}, is_local=True, tailscale=(True, False))
gp = {x["port_num"]: x for x in g}
check("panel port: ...and with Tailscale UP it is closeable again",
      not gp["5000"]["is_panel"] and not gp["5000"]["protected"],
      "is_panel=%s protected=%s" % (gp["5000"]["is_panel"], gp["5000"]["protected"]))

# An unreadable config.json degrades to DEFAULT_CONFIG and says nothing, so `port` answered 5000
# about a panel listening on 8443: the live 8443 rule kept a plain ×, and a phantom protection was
# computed for a port with no rule behind it. The last config this PROCESS parsed is the file the
# running listener was started from, so that is the reading to answer with.
_o_cfg_cache = dict(config._cfg_cache)
try:
    config._cfg_cache["data"] = {"port": 8443}
    g = protect(NS(port=22), ["22/tcp ALLOW IN Anywhere", "5000/tcp ALLOW IN Anywhere",
                              "8443/tcp ALLOW IN Anywhere"], is_local=True, cfg_unreadable=True)
    gp = {x["port_num"]: x for x in g}
    check("panel port: a CORRUPT config still protects the port the process actually bound",
          gp["8443"]["is_panel"] and gp["8443"]["protected"],
          "is_panel=%s protected=%s" % (gp["8443"]["is_panel"], gp["8443"]["protected"]))
    check("panel port: ...and does not protect DEFAULT_CONFIG's 5000 in its place",
          not gp["5000"]["is_panel"] and not gp["5000"]["protected"],
          "is_panel=%s protected=%s" % (gp["5000"]["is_panel"], gp["5000"]["protected"]))
    # Positive control: a READABLE config is still answered from the file, not from the cache.
    config._cfg_cache["data"] = {"port": 8443}
    g = protect(NS(port=22), ["22/tcp ALLOW IN Anywhere", "5000/tcp ALLOW IN Anywhere",
                              "8443/tcp ALLOW IN Anywhere"], cfg={"port": 5000}, is_local=True)
    gp = {x["port_num"]: x for x in g}
    check("panel port: a readable config still answers from what it says (5000)",
          gp["5000"]["is_panel"] and not gp["8443"]["is_panel"],
          "5000=%s 8443=%s" % (gp["5000"]["is_panel"], gp["8443"]["is_panel"]))
finally:
    config._cfg_cache.clear()
    config._cfg_cache.update(_o_cfg_cache)

# ── remote_ufw_status: "not installed" is an EXIT CODE, never text out of the rule table ───────
# `out` is the whole `ufw status numbered` listing, comments and all, and those comments are typed
# into this page's own "Open a Port" box (the validator accepts `[A-Za-z0-9 _.-]{0,60}`). One rule
# commented "plex not installed yet" made the entire host read as "UFW is not installed": empty
# rules table, "No IPs are blocked", every delete refused with "there's no rule N to delete", and
# nothing in the UI hinting why — until somebody removed that rule by hand over SSH.
_o_rp_fw, _o_ts_fw = _sm_core.run_privileged, _sm_hosts._tailscale_conn_state
try:
    _sm_hosts._tailscale_conn_state = lambda s: (False, False)   # no live probe from a unit test
    _UFW_OUT = ("Status: active\n\n"
                "     To                         Action      From\n"
                "     --                         ------      ----\n"
                "[ 1] 22/tcp                     ALLOW IN    Anywhere\n"
                "[ 2] 32400/tcp                  ALLOW IN    Anywhere   # plex not installed yet\n")
    _sm_core.run_privileged = lambda *a, **k: (_UFW_OUT, "", 0)
    _st = _sm_firewall.remote_ufw_status(NS(port=22))
    check("ufw status: a rule COMMENT saying 'not installed' does not erase the firewall",
          _st["installed"] is True and _st["enabled"] is True and len(_st["rules"]) == 2,
          "installed=%s enabled=%s rules=%d" % (_st["installed"], _st["enabled"], len(_st["rules"])))
    # ufw's Status line is gettext-translated whole — a Dutch host prints `Status: actief` — while
    # the rule rows and the header's dashed underline never are. Comparing the value to "active"
    # read that LIVE firewall as off: the badge said Inactive, and the lockout guard skips every
    # rule when the firewall is off, so the host's only SSH rule got a plain delete ×.
    _sm_core.run_privileged = lambda *a, **k: (
        "Status: actief\n\n"
        "     Naar                       Actie       Van\n"
        "     ----                       -----       ---\n"
        "[ 1] 22/tcp                     ALLOW IN    Anywhere\n", "", 0)
    _st = _sm_firewall.remote_ufw_status(NS(port=22))
    _ssh_g = [g for g in _st.get("groups", []) if g.get("port_num") == "22"]
    check("ufw status: a translated Status line on a LIVE firewall still reads as active",
          _st.get("enabled") is True, repr(_st)[:200])
    check("ufw status: ...so its only SSH rule is still protected from deletion",
          _ssh_g and _ssh_g[0].get("protected") is True,
          "groups %r — the last way in is deletable" % (_st.get("groups"),))
    # French translates the WORD too — `État : actif` — so the literal "Status:" is not there at
    # all. The gate here required it and called a live French firewall unreachable, after the two
    # copies of the same gate in hosts.py had already been fixed.
    _sm_core.run_privileged = lambda *a, **k: (
        "État : actif\n\n"
        "     Vers                       Action      De\n"
        "     ----                       ------      --\n"
        "[ 1] 22/tcp                     ALLOW IN    Anywhere\n", "", 0)
    _st = _sm_firewall.remote_ufw_status(NS(port=22))
    check("ufw status: a French host (no literal 'Status:') is read, not called unreachable",
          not _st.get("unreachable") and _st.get("enabled") is True and len(_st.get("rules") or []) == 1,
          repr(_st)[:200])
    _sm_core.run_privileged = lambda *a, **k: ("Status: inactief\n", "", 0)
    _st = _sm_firewall.remote_ufw_status(NS(port=22))
    check("ufw status: ...while a translated INACTIVE firewall (no rule listing) is inactive "
          "(positive control)", _st.get("installed") is True and _st.get("enabled") is False, repr(_st))
    # Positive control: the tool genuinely being absent is rc 127, and still reads as absent —
    # note the helper's own stderr for that case also contains "not installed".
    _sm_core.run_privileged = lambda *a, **k: (
        "panel-helper: the tool for ufw-status is not installed", "", 127)
    _st = _sm_firewall.remote_ufw_status(NS(port=22))
    check("ufw status: rc 127 still means UFW is genuinely not installed",
          _st["installed"] is False and not _st.get("unreachable"), repr(_st))
    # ...and a transport failure is still 'unreachable' rather than 'there is no firewall here'.
    _sm_core.run_privileged = lambda *a, **k: ("", "SSH command timed out", -1)
    _st = _sm_firewall.remote_ufw_status(NS(port=22))
    check("ufw status: a timed-out read is unreachable, not 'UFW is not installed'",
          _st.get("unreachable") is True and not _st.get("permission_denied"), repr(_st))
    # A sudo refusal is not a network fact. On the panel's own host this read is
    # `sudo -n <helper> ufw-status`, and a broadened sudoers grant makes it exit 1 with "a
    # password is required" — which was reported as "the panel can't reach this host", about the
    # machine the page was being served from, with nothing anywhere naming sudo.
    for _refusal in ("sudo: a password is required",
                     "sudo: no tty present and no askpass program available",
                     "ERROR: You need to be root to run this script"):
        _sm_core.run_privileged = lambda *a, _r=_refusal, **k: (_r, "", 1)
        _st = _sm_firewall.remote_ufw_status(NS(port=22))
        check("ufw status: %r is reported as a privilege refusal" % _refusal[:28],
              _st.get("permission_denied") is True, repr(_st))
    # ...and an operator's rule comment must not be able to forge that flag either.
    _sm_core.run_privileged = lambda *a, **k: (
        "[ 1] 22/tcp ALLOW IN Anywhere # sudo a password is required", "", 1)
    _st = _sm_firewall.remote_ufw_status(NS(port=22))
    check("ufw status: a rule comment cannot forge the privilege-refusal flag",
          _st.get("unreachable") is True and not _st.get("permission_denied"), repr(_st))
finally:
    _sm_core.run_privileged, _sm_hosts._tailscale_conn_state = _o_rp_fw, _o_ts_fw

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
_orig_ragu_first = _sm_core.run_as_game_user   # restored after the second stub below
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
try:
    _sm_core.run_as_game_user = lambda *a, **k: (_SRC_DETAILS, "", 0)
    res = _sm_game.detect_game_ports(NS(), "srv")
    eq("source: opens game + query only", res["open_ports"], [27015, 27016])
finally:
    # Restored. A stub left installed is not merely untidy: part03's own later blocks capture
    # `_orig = <module>.<attr>` to restore it, and a leaked stub is what they capture — so they
    # put the STUB back believing it is the original. That is the mechanism that silently
    # disabled the rest of this file once before.
    _sm_core.run_as_game_user = _orig_ragu_first

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
                               environ_base={"REMOTE_ADDR": "203.0.113.9"}):
    eq("direct connection: ignore spoofed XFF, use socket", client_ip(), "203.0.113.9")

# ...and loopback is not a proxy by itself. Every local account on the panel host can dial
# 127.0.0.1 — the game-server users included — so trusting any loopback peer let one of them pick
# a fresh throttle bucket per attempt, or name the admin's IP until fail2ban banned it. Only a
# loopback peer whose socket ROOT owns (tailscaled) is believed. Proved against the real kernel:
# a loopback pair opened here is owned by this (non-root) test process.
import socket as _lp_sock                                                            # noqa: E402
import tempfile as _lp_tmp                                                           # noqa: E402
from panel.security import auth as _lp_auth                                          # noqa: E402
from unit.part01 import skip as _lp_skip                                             # noqa: E402
_lp_srv = _lp_sock.socket(_lp_sock.AF_INET, _lp_sock.SOCK_STREAM)
_lp_srv.bind(("127.0.0.1", 0))
_lp_srv.listen(1)
_lp_cli = _lp_sock.socket(_lp_sock.AF_INET, _lp_sock.SOCK_STREAM)
_lp_cli.connect(_lp_srv.getsockname())
_lp_conn, _lp_peer = _lp_srv.accept()
_lp_env = {"REMOTE_ADDR": "127.0.0.1", "REMOTE_PORT": str(_lp_peer[1]),
           "SERVER_NAME": _lp_conn.getsockname()[0],       # what eventlet puts there
           "SERVER_PORT": str(_lp_srv.getsockname()[1])}
try:
    eq("loopback peer: the kernel names who dialled (this process's uid)",
       _lp_auth._loopback_peer_uid(_lp_env), os.getuid())
    eq("loopback peer: a port that matches no connection answers None, not a guess",
       _lp_auth._loopback_peer_uid(dict(_lp_env, REMOTE_PORT="1")), None)
    with _app.test_request_context(headers={"X-Forwarded-For": "1.2.3.4"},
                                   environ_overrides=_lp_env):
        from flask import request as _lp_req
        _lp_got = client_ip()
        # ...and it was refused BECAUSE the kernel named a non-root owner, not because the lookup
        # failed on a fixture environ (which would also answer 127.0.0.1).
        _lp_uid_seen = _lp_auth._loopback_peer_uid(_lp_req.environ)
    if os.getuid() != 0:
        check("loopback peer: a NON-root local caller's X-Forwarded-For is ignored",
              _lp_got == "127.0.0.1" and _lp_uid_seen == os.getuid(),
              "client_ip=%r, owner seen=%r" % (_lp_got, _lp_uid_seen))
    else:
        _lp_skip("loopback peer: a NON-root local caller's X-Forwarded-For is ignored",
             "the suite is running as root, so this connection IS root-owned")
finally:
    for _s in (_lp_conn, _lp_cli, _lp_srv):
        _s.close()
# ...and a local account that writes its request and hangs up at once is not root either. The
# orphaned client end becomes a FIN_WAIT2 time-wait entry, which the kernel prints with uid 0 —
# while the panel still reads the whole buffered request, forged X-Forwarded-For included. Matching
# any row by its ports read that 0 as tailscaled and believed the header: auth.log and fail2ban
# then named the admin's address, no response needed. Real kernel, real close().
import time as _lp_time                                                              # noqa: E402
_lp_srv = _lp_sock.socket(_lp_sock.AF_INET, _lp_sock.SOCK_STREAM)
_lp_srv.bind(("127.0.0.1", 0))
_lp_srv.listen(1)
_lp_cli = _lp_sock.socket(_lp_sock.AF_INET, _lp_sock.SOCK_STREAM)
_lp_cli.connect(_lp_srv.getsockname())
_lp_conn, _lp_peer = _lp_srv.accept()
_lp_env = {"REMOTE_ADDR": "127.0.0.1", "REMOTE_PORT": str(_lp_peer[1]),
           "SERVER_NAME": _lp_conn.getsockname()[0], "SERVER_PORT": str(_lp_srv.getsockname()[1])}
try:
    _lp_cli.sendall(b"POST /login HTTP/1.1\r\nX-Forwarded-For: 1.2.3.4\r\n\r\n")
    _lp_cli.close()
    _lp_row = None
    # Until the time-wait entry (FIN_WAIT2 05 / TIME_WAIT 06) — the uid-0 shape. FIN_WAIT1 comes
    # first and lasts until the server's delayed ACK (up to ~200ms); on this kernel it still names
    # the real owner, so stopping there tests nothing. Bounded, not a fixed sleep.
    for _ in range(150):
        with open("/proc/net/tcp") as _fh:
            _lp_row = next((_c for _c in (_l.split() for _l in _fh)
                            if _c[1:2] == ["0100007F:%04X" % _lp_peer[1]]), None)
        if _lp_row is not None and _lp_row[3] in ("05", "06"):
            break
        _lp_time.sleep(0.02)
    _lp_buffered = _lp_conn.recv(4096)
    with _app.test_request_context(headers={"X-Forwarded-For": "1.2.3.4"},
                                   environ_overrides=_lp_env):
        _lp_got = client_ip()
    check("loopback peer: a client that sent and hung up (its row now uid 0) is NOT trusted",
          _lp_got == "127.0.0.1",
          "client_ip=%r from a closed local socket whose row reads state=%s uid=%s inode=%s"
          % (_lp_got, *(_lp_row[i] if _lp_row else "?" for i in (3, 7, 9))))
    # ...and the row really is the root-looking time-wait one, and the request really was still
    # there to act on — otherwise the check above passes on a vanished row, which proves nothing.
    check("loopback peer: ...its row is still listed, as time-wait, and the request readable",
          _lp_row is not None and _lp_row[3] in ("05", "06") and b"X-Forwarded-For" in _lp_buffered,
          "row=%r buffered=%r" % (_lp_row and _lp_row[:10], _lp_buffered[:60]))
finally:
    for _s in (_lp_conn, _lp_cli, _lp_srv):
        _s.close()
# Rows are matched on whole addresses now, spelled the kernel's way — so ::1 (Serve dialling
# "localhost") must still find its row, or tailscaled over IPv6 silently stops being trusted.
try:
    _lp6_srv = _lp_sock.socket(_lp_sock.AF_INET6, _lp_sock.SOCK_STREAM)
    _lp6_srv.bind(("::1", 0))
except OSError as _e:
    _lp6_srv = None
    _lp_skip("loopback peer: the kernel names who dialled over ::1 too", "no IPv6 here: %s" % _e)
if _lp6_srv is not None:
    _lp6_srv.listen(1)
    _lp6_cli = _lp_sock.socket(_lp_sock.AF_INET6, _lp_sock.SOCK_STREAM)
    _lp6_cli.connect(_lp6_srv.getsockname()[:2])
    _lp6_conn, _lp6_peer = _lp6_srv.accept()
    try:
        eq("loopback peer: the kernel names who dialled over ::1 too",
           _lp_auth._loopback_peer_uid({"REMOTE_ADDR": "::1", "REMOTE_PORT": str(_lp6_peer[1]),
                                        "SERVER_NAME": _lp6_conn.getsockname()[0],
                                        "SERVER_PORT": str(_lp6_conn.getsockname()[1])}),
           os.getuid())
    finally:
        for _s in (_lp6_conn, _lp6_cli, _lp6_srv):
            _s.close()
# A panel bound DUAL-STACK ('::') sees an IPv4 client as ::ffff:127.0.0.1, while the client's own
# row is in /proc/net/tcp. Looking it up in tcp6 found nothing, so Tailscale Serve dialling
# 127.0.0.1 was never trusted there and every Serve user shared one throttle bucket.
try:
    _lpd_srv = _lp_sock.socket(_lp_sock.AF_INET6, _lp_sock.SOCK_STREAM)
    _lpd_srv.setsockopt(_lp_sock.IPPROTO_IPV6, _lp_sock.IPV6_V6ONLY, 0)
    _lpd_srv.bind(("::", 0))
except OSError as _e:
    _lpd_srv = None
    _lp_skip("loopback peer: an IPv4 client of a dual-stack bind is found", "no dual-stack: %s" % _e)
if _lpd_srv is not None:
    _lpd_srv.listen(1)
    _lpd_cli = _lp_sock.socket(_lp_sock.AF_INET, _lp_sock.SOCK_STREAM)
    _lpd_cli.connect(("127.0.0.1", _lpd_srv.getsockname()[1]))
    _lpd_conn, _lpd_peer = _lpd_srv.accept()
    try:
        check("loopback peer: (setup) the dual-stack socket sees the IPv4 client as mapped",
              _lpd_peer[0] == "::ffff:127.0.0.1", repr(_lpd_peer))
        eq("loopback peer: an IPv4 client of a dual-stack bind is found (not looked for in tcp6)",
           _lp_auth._loopback_peer_uid({"REMOTE_ADDR": _lpd_peer[0], "REMOTE_PORT": str(_lpd_peer[1]),
                                        "SERVER_NAME": _lpd_conn.getsockname()[0],
                                        "SERVER_PORT": str(_lpd_conn.getsockname()[1])}),
           os.getuid())
    finally:
        for _s in (_lpd_conn, _lpd_cli, _lpd_srv):
            _s.close()
# The trusted side, from a socket table naming root as the owner (the tailscaled shape).
_lp_fix = os.path.join(_lp_tmp.mkdtemp(), "tcp")
with open(_lp_fix, "w") as _fh:
    _fh.write("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt"
              "   uid  timeout inode\n"
              "   0: 0100007F:A1B2 0100007F:1388 01 00000000:00000000 00:00000000 00000000"
              "     0        0 12345 1 0000000000000000 20 4 30 10 -1\n"
              "   1: 0100007F:C3D4 0100007F:1388 01 00000000:00000000 00:00000000 00000000"
              "  1001        0 12346 1 0000000000000000 20 4 30 10 -1\n"
              # A time-wait entry: what a local client's socket becomes once it sends and closes.
              "   2: 0100007F:E5F6 0100007F:1388 06 00000000:00000000 03:00001770 00000000"
              "     0        0 0 3 0000000000000000\n"
              # A ROOT connection between two other addresses that happens to share BOTH port
              # numbers with a uid-1001 loopback client listed after it.
              "   3: 0A000005:B1B2 0A000009:1388 01 00000000:00000000 00:00000000 00000000"
              "     0        0 22222 1 0000000000000000 20 4 30 10 -1\n"
              "   4: 0100007F:B1B2 0100007F:1388 01 00000000:00000000 00:00000000 00000000"
              "  1001        0 22223 1 0000000000000000 20 4 30 10 -1\n"
              # No socket inode: no process owns this end, whatever the uid column says.
              "   5: 0100007F:D7D8 0100007F:1388 01 00000000:00000000 00:00000000 00000000"
              "     0        0 0 1 0000000000000000 20 4 30 10 -1\n")
_lp_saved = dict(_lp_auth._PROC_NET_TCP)
_lp_auth._PROC_NET_TCP[4] = _lp_fix
try:
    for _port, _want, _label in ((0xA1B2, "1.2.3.4", "a ROOT-owned loopback peer (tailscaled) is"),
                                 (0xC3D4, "127.0.0.1", "a uid-1001 loopback peer is NOT"),
                                 (0xE5F6, "127.0.0.1",
                                  "a time-wait row (printed uid 0, inode 0) is NOT"),
                                 (0xB1B2, "127.0.0.1",
                                  "a root row on OTHER addresses with the same ports is NOT"),
                                 (0xD7D8, "127.0.0.1",
                                  "an ESTABLISHED row with no socket inode (no owner) is NOT")):
        with _app.test_request_context(headers={"X-Forwarded-For": "1.2.3.4"},
                                       environ_overrides={"REMOTE_ADDR": "127.0.0.1",
                                                     "REMOTE_PORT": str(_port),
                                                     "SERVER_NAME": "127.0.0.1",
                                                     "SERVER_PORT": "5000"}):
            eq("loopback proxy: %s trusted for X-Forwarded-For" % _label, client_ip(), _want)
finally:
    _lp_auth._PROC_NET_TCP.clear()
    _lp_auth._PROC_NET_TCP.update(_lp_saved)

# ── TOTP (2FA) ────────────────────────────────────────────────
import time as _time
from panel.security.auth import generate_totp_secret, verify_totp
import pyotp as _pyotp
_sec = generate_totp_secret()
check("verify_totp accepts the current code", verify_totp(_sec, _pyotp.TOTP(_sec).now()))
check("verify_totp accepts a spaced code", verify_totp(_sec, " " + _pyotp.TOTP(_sec).now() + " "))
check("verify_totp rejects a wrong code", not verify_totp(_sec, "000000"))
check("verify_totp rejects empty", not verify_totp(_sec, ""))

# ── a branch switch that never launched must not leave the panel TRACKING that branch ────────
# panel_switch_branch writes panel_branch into config BEFORE launching the installer, and the
# launch really can fail ("install.sh is missing, so the panel can't self-update safely"). The
# route then reports success:false and audits a failure — while the panel tracks a branch its
# checkout is not on. _tracked_branch() reads that key, so the next ordinary "Update" would hand
# install.sh the branch nobody switched to and reset the checkout onto it. The update-status CI
# gate does not save you: it refuses only "pending"/"failing", and a non-default branch reports
# "unverified", which passes.
from panel.core import config as SO_cfgmod   # noqa: E402
_sb_saved = (SO._git, SO._is_git_checkout, SO._launch_installer)
_sb_cfg_saved = (SO_cfgmod.load_config, SO_cfgmod.update_config)
try:
    _sb_cfg = {"panel_branch": "main"}
    SO_cfgmod.load_config = lambda: dict(_sb_cfg)
    SO_cfgmod.update_config = lambda fn: (fn(_sb_cfg), dict(_sb_cfg))[1]
    SO._is_git_checkout = lambda: True
    SO._git = lambda args, timeout=20, **k: ("", "", 0)      # the branch exists on the remote

    SO._launch_installer = lambda target_ref="", branch="", started_msg=None: (
        False, "install.sh is missing, so the panel can't self-update safely.")
    _ok, _msg = SO.panel_switch_branch("some-feature-branch")
    check("switch-branch: a launch that failed is reported as a failure", _ok is False, _msg)
    check("switch-branch: ...and the tracked branch is left where it was",
          _sb_cfg.get("panel_branch") == "main",
          "config now tracks %r, so the next ordinary Update would switch the checkout onto it"
          % (_sb_cfg.get("panel_branch"),))

    # The control: a launch that STARTS does move the tracked branch, or the guard above would
    # just be "never record anything".
    SO._launch_installer = lambda target_ref="", branch="", started_msg=None: (True, "started")
    _ok2, _ = SO.panel_switch_branch("some-feature-branch")
    check("switch-branch: a launch that started DOES record the new branch",
          _ok2 is True and _sb_cfg.get("panel_branch") == "some-feature-branch",
          "tracked %r" % (_sb_cfg.get("panel_branch"),))
finally:
    (SO._git, SO._is_git_checkout, SO._launch_installer) = _sb_saved
    (SO_cfgmod.load_config, SO_cfgmod.update_config) = _sb_cfg_saved

# ── ...and "Update started" has to mean the updater actually STARTED ──────────────────────────
# The guard above only works if _launch_installer can say no. The non-helper path — the one the
# live per-user install takes — launched the wrapper with subprocess.Popen, both streams to
# DEVNULL, and returned success unconditionally. Popen reports only that the child was SPAWNED,
# and `systemd-run --no-block` schedules the unit and exits within milliseconds with a REAL exit
# status: a refusal (the unit name still held by a running panel-selfupdate, no user D-Bus
# session, `sudo systemd-run` denied by a later sudoers.d rule) was completely silent while the
# panel asserted the whole snapshot → update → health-check → auto-rollback sequence, and
# panel_switch_branch's rollback never fired. The helper branch 25 lines up already checked rc.
import tempfile as _li_tmp, shutil as _li_sh   # noqa: E402

# A throwaway PANEL_DIR: _launch_installer writes its wrapper into <PANEL_DIR>/data, and no test
# writes into a real data dir.
_li_dir = _li_tmp.mkdtemp(prefix="panel-launch-")
with open(os.path.join(_li_dir, "install.sh"), "w") as _li_fh:
    _li_fh.write("#!/bin/bash\n")
_li_saved = (SO.PANEL_DIR, SO._is_system_service, SO._helper_present,
             SO.subprocess.Popen, SO.subprocess.run)
_li_rc, _li_popen = {"rc": 1}, []
try:
    SO.PANEL_DIR = _li_dir
    SO._is_system_service = lambda: False      # the per-user Popen path these checks describe
    SO._helper_present = lambda: False
    # Recorded, not raising: a regression back to Popen would otherwise land in the function's own
    # `except Exception` and answer False, which is what the first check is looking for.
    SO.subprocess.Popen = lambda *a, **k: (_li_popen.append(a), type("P", (), {})())[1]
    SO.subprocess.run = lambda *a, **k: type(
        "R", (), {"returncode": _li_rc["rc"],
                  "stderr": "Unit panel-selfupdate.service already exists."})()
    _li_ok, _li_msg = SO._launch_installer()
    check("self-update: a launcher that REFUSED is not reported as an update that started",
          _li_ok is False and "Could not start the updater" in _li_msg, str((_li_ok, _li_msg)))
    check("self-update: ...and the launch is a CHECKED call, not fire-and-forget Popen",
          not _li_popen, "subprocess.Popen was used, so the exit status is unreadable")
    _li_rc["rc"] = 0
    _li_ok2, _li_msg2 = SO._launch_installer()
    check("self-update: ...while a launcher that started still reports the update (control)",
          _li_ok2 is True and "Update started" in _li_msg2, str((_li_ok2, _li_msg2)))
    # The same unconditional-True shape was in panel_repair_database's fallback: `systemd-run
    # --on-active=2` also returns at once with a real status, so a refusal told the user their
    # database was being repaired offline while nothing ever ran and the flagged DB stayed flagged.
    os.makedirs(os.path.join(_li_dir, "venv", "bin"), exist_ok=True)
    for _li_p in (os.path.join(_li_dir, "venv", "bin", "python3"),
                  os.path.join(_li_dir, "db_maintenance.py")):
        with open(_li_p, "w") as _li_fh2:
            _li_fh2.write("")
    _li_rc["rc"] = 1
    _li_rok, _li_rmsg = SO.panel_repair_database()
    check("db-repair: a repair job that never started is not reported as a repair in progress",
          _li_rok is False and "Couldn't start the repair job" in _li_rmsg,
          str((_li_rok, _li_rmsg)))
    _li_rc["rc"] = 0
    check("db-repair: ...while one that did start still reports it (control)",
          SO.panel_repair_database()[0] is True, str(SO.panel_repair_database()))
finally:
    (SO.PANEL_DIR, SO._is_system_service, SO._helper_present,
     SO.subprocess.Popen, SO.subprocess.run) = _li_saved
    _li_sh.rmtree(_li_dir, ignore_errors=True)

# ── remote_uptime says whether the host actually ANSWERED ────────────────────────────────────
# Its placeholder dict ("uptime": "unknown", load/disk/memory/cpu all "?") is what comes back when
# nothing was read — and it is indistinguishable from a successful parse of a field that was
# missing, because that path writes the same words. The helper itself has always known the
# difference: it refuses to put a failed read in its own cache. Callers that PERSIST the dict need
# the same fact, so it is now on the dict.
from panel.ops.ssh_manager import hosts as _up_hosts, _core as _up_core   # noqa: E402

_up_saved = _up_core.run_command
_up_ns = type("NS", (), {})
try:
    _up_hosts._uptime_cache.clear()
    _up_core.run_command = lambda *a, **k: ("", "ssh: connect to host ... timed out", -1)
    _srv = _up_ns(); _srv.id = 90001
    _d_fail = _up_hosts.remote_uptime(_srv, force=True)
    check("remote_uptime: a read that never happened says so",
          _d_fail.get("read_ok") is False, "read_ok=%r" % _d_fail.get("read_ok"))
    check("remote_uptime: ...and is not cached, as it never was",
          _srv.id not in _up_hosts._uptime_cache)
    _up_core.run_command = lambda *a, **k: (
        "UPTIME up 3 days\nLOAD 0.1 0.2 0.3\nDISK 5G/20G\nMEM 1G/4G\nMEMPCT 25.0\n", "", 0)
    _up_hosts._uptime_cache.clear()
    _srv2 = _up_ns(); _srv2.id = 90002
    _d_ok = _up_hosts.remote_uptime(_srv2, force=True)
    check("remote_uptime: a real reading says so too", _d_ok.get("read_ok") is True,
          "read_ok=%r uptime=%r" % (_d_ok.get("read_ok"), _d_ok.get("uptime")))
finally:
    _up_core.run_command = _up_saved
    _up_hosts._uptime_cache.clear()

# ── no ROUTE may consume a live code with the yes/no form ────────────────────────────────────
# verify_totp answers "is it valid", which is not enough: a code is good for ~90s, so an observed
# one stays usable for the rest of that window unless the step it used is SPENT. Three routes take
# a live code — login step 2, the password change, and 2FA enrolment — and the first two were
# converted to verify_totp_step while enrolment was missed, leaving the code that turned 2FA on
# still able to sign the account in.
#
# Read from the AST, because the fixed routes carry comments that say "verify_totp_STEP, not
# verify_totp" — a substring gate matches the prose that documents the fix.
import ast as _totp_ast
_totp_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_totp_bad = []
for _rel in ["app.py"] + ["panel/" + _p for _p in [
        "routes/auth_routes.py", "routes/tags.py", "routes/admin_notifications.py",
        "security/auth.py"]]:
    _path = os.path.join(_totp_root, _rel)
    if not os.path.exists(_path):
        continue
    _tree = _totp_ast.parse(open(_path, encoding="utf-8").read())
    for _n in _totp_ast.walk(_tree):
        if not (isinstance(_n, _totp_ast.Call)
                and getattr(_n.func, "id", getattr(_n.func, "attr", None)) == "verify_totp"):
            continue
        # its own definition site is allowed to exist; callers are not
        _totp_bad.append("%s:%d" % (_rel, _n.lineno))
check("2FA: no route consumes a live code with the yes/no verify_totp",
      not _totp_bad,
      "verify_totp is called at %s — use verify_totp_step and record the step, or an observed "
      "code stays replayable for the rest of its window" % ", ".join(_totp_bad))

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

# ── bcrypt runs OFF the eventlet hub ────────────────────────────────────────────────────────
# bcrypt is a native call that never yields, and the panel is one eventlet hub: every /login POST
# (unauthenticated, including the dummy compare for an unknown username) held every page, console
# and poller for a whole cost-12 hash. Under a monkey-patched runtime each bcrypt call must go
# through eventlet.tpool. The suite is not monkey-patched, so the patch check and tpool.execute are
# stubbed and the REAL password, dummy and backup-code functions are driven through them.
import eventlet.patcher as _bh_patcher                                               # noqa: E402
import eventlet.tpool as _bh_tpool                                                   # noqa: E402
import bcrypt as _bh_bcrypt                                                          # noqa: E402
from panel.db.models import User as _BhUser                                          # noqa: E402
_bh_saved = (_bh_patcher.is_monkey_patched, _bh_tpool.execute)
_bh_calls = []


def _bh_exec(fn, *a, **k):
    _bh_calls.append(fn)
    return fn(*a, **k)


try:
    _bh_patcher.is_monkey_patched = lambda name: True
    _bh_tpool.execute = _bh_exec
    _bh_hash = hash_password("Off-hub1!pass")
    _bh_ok = check_password("Off-hub1!pass", _bh_hash)
    _bh_bad = check_password("wrong", _bh_hash)
    _bh_calls_pw = list(_bh_calls)
    del _bh_calls[:]
    dummy_password_check("anything")
    _bh_calls_dummy = list(_bh_calls)
    del _bh_calls[:]
    _bh_u = _BhUser(username="offhub")
    _bh_u.set_backup_codes(["abcde-fghij"])
    _bh_used = _bh_u.use_backup_code("ABCDE-FGHIJ")
    _bh_calls_codes = list(_bh_calls)
finally:
    _bh_patcher.is_monkey_patched, _bh_tpool.execute = _bh_saved
check("bcrypt off-hub: hash + both checks go through tpool, and still answer correctly",
      _bh_calls_pw == [_bh_bcrypt.hashpw, _bh_bcrypt.checkpw, _bh_bcrypt.checkpw]
      and _bh_ok is True and _bh_bad is False, "%r ok=%r bad=%r" % (_bh_calls_pw, _bh_ok, _bh_bad))
check("bcrypt off-hub: the unknown-username dummy compare goes through tpool too",
      _bh_bcrypt.checkpw in _bh_calls_dummy, repr(_bh_calls_dummy))
check("bcrypt off-hub: backup codes are hashed and checked through tpool",
      _bh_calls_codes == [_bh_bcrypt.hashpw, _bh_bcrypt.checkpw] and _bh_used is True,
      "%r used=%r" % (_bh_calls_codes, _bh_used))
# Off eventlet (manage.py, a bare script) it is a plain call: tpool is not touched at all. Stated
# explicitly, because THIS suite is monkey-patched — importing app runs eventlet.monkey_patch().
del _bh_calls[:]
_bh_patcher.is_monkey_patched = lambda name: False
_bh_tpool.execute = _bh_exec
try:
    _bh_plain = check_password("Off-hub1!pass", _bh_hash)
finally:
    _bh_patcher.is_monkey_patched, _bh_tpool.execute = _bh_saved
check("bcrypt off-hub: without monkey-patching it is a direct call (control)",
      _bh_plain is True and _bh_calls == [], repr(_bh_calls))

# ── the login and token throttles count an IPv6 client by its /64 ───────────────────────────
from panel.security.auth import throttle_key as _tk_fn                              # noqa: E402
for _tk_in, _tk_want in (("203.0.113.9", "203.0.113.9"),
                         ("2001:db8:1:2:aaaa::1", "2001:db8:1:2::/64"),
                         ("2001:db8:1:2:ffff:ffff:ffff:ffff", "2001:db8:1:2::/64"),
                         ("::ffff:203.0.113.9", "203.0.113.9"),
                         ("unknown", "unknown")):
    eq("throttle key: %s -> %s" % (_tk_in, _tk_want), _tk_fn(_tk_in), _tk_want)

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


# ── a locally-spawned child never inherits the PANEL's stdin ────────────────────────────────────
# Popen's default is to inherit fd 0. tools/panel-helper's Python verbs read stdin to EOF, so a
# panel started anywhere but under systemd (which supplies /dev/null) handed them a descriptor that
# never closed and every such verb timed out. The helper no longer reads stdin it was sent nothing
# on; this is the other half — the panel does not expose its input to a child in the first place,
# which holds whatever the child decides to do with it.
#
# fd 0 is replaced with the read end of a pipe whose WRITE end is held open, so an inherited stdin
# blocks and a DEVNULL stdin reads "" at once. Without that substitution the suite's own fd 0 is
# already /dev/null on most runners and both branches would pass.
import subprocess as _sp2
import sys as _sys2

_READER = "import sys; sys.stdout.write('READ:%r' % sys.stdin.read())"
_r_fd, _w_fd = os.pipe()
_saved_fd0 = os.dup(0)
try:
    os.dup2(_r_fd, 0)
    _argv_out, _argv_err, _argv_rc = _sm_core._exec_local_argv(
        [_sys2.executable, "-c", _READER], timeout=8)
    _sh_out, _sh_err, _sh_rc = _sm_core._exec_local_shell(
        "%s -c %s" % (_sys2.executable, _sm_core._quote(_READER)), timeout=8)
    _so_out, _so_err, _so_rc = SO._run(
        "%s -c %s" % (_sys2.executable, _sm_core._quote(_READER)), timeout=8)
    # The PIPE branch must still deliver a payload to the verbs that do want one.
    _fed_out, _fed_err, _fed_rc = _sm_core._exec_local_argv(
        [_sys2.executable, "-c", _READER], timeout=8, stdin_text="payload")
finally:
    os.dup2(_saved_fd0, 0)
    for _fd in (_saved_fd0, _r_fd, _w_fd):
        try:
            os.close(_fd)
        except OSError:
            pass

check("local exec: _exec_local_argv gives the child DEVNULL, not the panel's stdin",
      _argv_rc == 0 and _argv_out == "READ:''", "rc=%r out=%r err=%r" % (_argv_rc, _argv_out[:60], _argv_err[:60]))
check("local exec: _exec_local_shell likewise",
      _sh_rc == 0 and _sh_out == "READ:''", "rc=%r out=%r err=%r" % (_sh_rc, _sh_out[:60], _sh_err[:60]))
check("local exec: system_ops._run likewise",
      _so_rc == 0 and _so_out == "READ:''", "rc=%r out=%r err=%r" % (_so_rc, _so_out[:60], _so_err[:60]))
check("local exec: ...and stdin_text still reaches the child that asked for it",
      _fed_rc == 0 and _fed_out == "READ:'payload'", "rc=%r out=%r" % (_fed_rc, _fed_out[:60]))
check("local exec: _POPEN_KW pins stdin to DEVNULL for every local spawn",
      _sm_core._POPEN_KW.get("stdin") is _sp2.DEVNULL, repr(_sm_core._POPEN_KW.get("stdin")))
# _run_verb picks input= only when the verb declares stdin text; otherwise DEVNULL.
_with_stdin = sorted(v for v, spec in _privmod._ARGV.items() if spec[2] is not None)
check("local exec: _run_verb sends a verb's declared stdin and nothing else's",
      _with_stdin == ["ufw-delete-num"] and _privmod.stdin_for("ufw-status") is None,
      "declared=%s of %d verbs" % (_with_stdin, len(_privmod._ARGV)))


# ── a mount change that needs a restart says so ────────────────────────────────────────────────
# gmod_mount_setup returned "Mounted: Counter-Strike: Source" the moment the files were written,
# and the route surfaces that string verbatim. Two things make it untrue for a RUNNING server:
# GMod reads mount.cfg once at startup, and content-grant-read's `usermod -aG` reaches only
# processes started after it. Measured on the test host — before the restart the srcds process had
# `Groups: 1003` and could not read one content file; after it, `Groups: 1003 1010` and GMod logged
# `Adding mount.cfg path: /home/gmodcontent/serverfiles/cstrike`. So the user was told their
# content was mounted while the running server could not see any of it.
_orig_gm_run, _orig_gm_priv = _sm_core.run_command, _sm_core.run_privileged
try:
    _gm_state = {"live": True}

    def _gm_run(server, cmd, timeout=30, sudo=True, **kw):
        if "__LIVE__" in cmd:                       # the liveness probe
            return ("__LIVE__", "", 0) if _gm_state["live"] else ("NO_SESSION", "", 3)
        if "base64 -d" in cmd:                      # the mount.cfg write
            return ("__OK__", "", 0)
        if cmd.startswith("id -gn"):
            # A real host answers this with the group name. The stub used to fall through to the
            # catch-all ("", "", 0), and gmod_mount_setup carried on because _user_primary_group
            # guessed the USERNAME when the read came back empty — the guess that fed `usermod -aG`
            # and is gone now. Answer it the way the host does.
            return ("gmodcontent", "", 0)
        return ("", "", 0)

    _sm_core.run_command = _gm_run
    _sm_core.run_privileged = lambda *a, **k: ("", "", 0)

    _gm_state["live"] = True
    _ok, _msg = _sm_gmod.gmod_mount_setup(NS(), "gmodserver", "gmodcontent", ["cstrike"])
    check("gmod mounts: a RUNNING server is told the change needs a restart",
          _ok is True and "Counter-Strike: Source" in _msg and "restart" in _msg.lower(), _msg)

    _gm_state["live"] = False
    _ok2, _msg2 = _sm_gmod.gmod_mount_setup(NS(), "gmodserver", "gmodcontent", ["cstrike"])
    check("gmod mounts: ...and a STOPPED server is not nagged to restart",
          _ok2 is True and "Counter-Strike: Source" in _msg2 and "restart" not in _msg2.lower(), _msg2)

    _gm_state["live"] = True
    _ok3, _msg3 = _sm_gmod.gmod_mount_setup(NS(), "gmodserver", "", [])
    check("gmod mounts: unmounting a running server needs the restart too",
          _ok3 is True and "Unmounted" in _msg3 and "restart" in _msg3.lower(), _msg3)

    # A liveness read that FAILS must warn, not stay silent: a spurious restart costs a restart,
    # a missing one costs the user content that silently is not there.
    def _gm_boom(*a, **k):
        raise OSError("ssh down")
    _sm_core.run_command = lambda server, cmd, **kw: (
        _gm_boom() if "__LIVE__" in cmd else ("__OK__", "", 0))
    _ok4, _msg4 = _sm_gmod.gmod_mount_setup(NS(), "gmodserver", "gmodcontent", ["cstrike"])
    check("gmod mounts: a liveness check that FAILS warns rather than claiming it is live",
          _ok4 is True and "restart" in _msg4.lower(), _msg4)
finally:
    _sm_core.run_command, _sm_core.run_privileged = _orig_gm_run, _orig_gm_priv


# ── a backup must never be deleted to make room the panel could not measure ─────────────────────
# backup_disk_info returns {"free": 0, "total": 0} on ANY failure (its rc is discarded), and
# free=0 is below every threshold — so a timed-out `df` sent _ensure_backup_headroom straight into
# its delete loop. Measured on the test host: with df working nothing was deleted; with the df read
# failing, two of four backups were deleted and the run reported "freed space first".
# run_game_backup's pre-flight check already states the rule — "Only enforce when we actually read
# the disk (total > 0); a failed df reads as 0/0" — but it guards the path that BLOCKS a backup,
# not the one that DELETES them.
_hr_orig = (_sm_cron.list_game_backups, _sm_cron.backup_disk_info, _sm_cron.delete_game_backup)
try:
    _hr = {"deleted": [], "disk": {"free": 0, "total": 0}}
    _BKS = [{"name": "s-2026-09-18-100000.tar.zst", "size": 1000},
            {"name": "s-2026-09-17-100000.tar.zst", "size": 1000},
            {"name": "s-2026-09-16-100000.tar.zst", "size": 1000},
            {"name": "s-2026-09-15-100000.tar.zst", "size": 1000}]
    _sm_cron.list_game_backups = lambda s, u: list(_BKS)
    _sm_cron.backup_disk_info = lambda s, u: _hr["disk"]
    _sm_cron.delete_game_backup = lambda s, u, n: (_hr["deleted"].append(n), True)[1]

    # THE BUG: a failed df is 0/0, and 0 free is below any threshold.
    _hr["deleted"], _hr["disk"] = [], {"free": 0, "total": 0}
    _note = _sm_cron._ensure_backup_headroom(NS(), "ut2k4srv", 3)
    check("backup headroom: a FAILED df deletes nothing", _hr["deleted"] == [], repr(_hr["deleted"]))
    check("backup headroom: ...and reports no freeing it did not do", _note == "", repr(_note))

    # A real, genuinely tight disk must still free space — the guard must not disable the feature.
    _hr["deleted"], _hr["disk"] = [], {"free": 500, "total": 10 ** 9}
    _note = _sm_cron._ensure_backup_headroom(NS(), "ut2k4srv", 3)
    check("backup headroom: a real tight disk still frees space", len(_hr["deleted"]) > 0, repr(_note))
    check("backup headroom: ...keeping the newest keep-1",
          "s-2026-09-18-100000.tar.zst" not in _hr["deleted"], repr(_hr["deleted"]))
    check("backup headroom: ...and deleting the OLDEST first",
          _hr["deleted"][0] == "s-2026-09-15-100000.tar.zst", repr(_hr["deleted"]))

    # A real, roomy disk deletes nothing.
    _hr["deleted"], _hr["disk"] = [], {"free": 10 ** 9, "total": 10 ** 9}
    check("backup headroom: a roomy disk deletes nothing",
          _sm_cron._ensure_backup_headroom(NS(), "ut2k4srv", 3) == "" and _hr["deleted"] == [])
finally:
    (_sm_cron.list_game_backups, _sm_cron.backup_disk_info,
     _sm_cron.delete_game_backup) = _hr_orig


# ── "couldn't tell" must not be reported as "clearly not installed" ─────────────────────────────
# _looks_installed documents three states — True / False / None — but its du fallback could only
# ever produce two. run_command does not raise on a transport failure (it returns
# ("", "…timed out", -1)), and `2>/dev/null` means a MISSING serverfiles dir prints nothing either,
# so both read as "" and `int("0") > 50` answered False: "clearly NOT installed".
#
# That verdict is acted on. app.py's reconcile ticker sets installed=False / status="failed" on it
# — while its own next line reads "None (host unreachable): leave it", which is exactly the case
# False was stealing — and manage_servers.py wipes lgsm/tmp and re-runs a 30-minute auto-install,
# three times over, for a server that had finished downloading.
import panel.routes._shared as _sh

# Stubbed on the DEFINING module. This used to assign _sh._sm.run_command — the ssh_manager
# PACKAGE — and "restore" it by assigning the real function back, which left a concrete attribute
# on the package that shadows its PEP 562 __getattr__ for the rest of the run: every later stub on
# _core.run_command was then silently missed by any caller reaching it as `_sm.run_command`.
_li_orig = _sm_core.run_command
try:
    _li = {"details": ("", "", 0), "du": ("", "", 0)}
    _sm_core.run_command = lambda r, c, **k: (_li["du"] if "du -sm" in c else _li["details"])
    _app = NS(logger=NS(debug=lambda *a, **k: None))

    # THE BUG: both reads fail, nothing raises.
    _li["details"], _li["du"] = ("", "SSH command timed out", -1), ("", "SSH command timed out", -1)
    check("_looks_installed: a FAILED read is 'couldn't tell', not 'not installed'",
          _sh._looks_installed(_app, NS(), "gmodserver", "gmodserver") is None,
          repr(_sh._looks_installed(_app, NS(), "gmodserver", "gmodserver")))

    # A serverfiles dir that really is absent: the command RAN, it just found nothing.
    _li["du"] = ("__DU_DONE__", "", 0)
    check("_looks_installed: an absent serverfiles really is False",
          _sh._looks_installed(_app, NS(), "gmodserver", "gmodserver") is False)

    # A completed download.
    _li["du"] = ("6100\n__DU_DONE__", "", 0)
    check("_looks_installed: a full serverfiles is True",
          _sh._looks_installed(_app, NS(), "gmodserver", "gmodserver") is True)

    # A tiny serverfiles is a failed download, not a complete one.
    _li["du"] = ("3\n__DU_DONE__", "", 0)
    check("_looks_installed: a nearly-empty serverfiles is still False",
          _sh._looks_installed(_app, NS(), "gmodserver", "gmodserver") is False)

    # The positive paths from `details` must be untouched.
    _li["details"] = ("Status: STARTED\nServer IP: 1.2.3.4", "", 0)
    check("_looks_installed: a real `details` answer still wins",
          _sh._looks_installed(_app, NS(), "gmodserver", "gmodserver") is True)
    _li["details"] = ("[ FAIL ] serverfiles not found — please run ./gmodserver install", "", 0)
    check("_looks_installed: ...and so does an explicit 'not installed'",
          _sh._looks_installed(_app, NS(), "gmodserver", "gmodserver") is False)

    # The caller side: the command must carry the marker, or the checks above pass without it.
    _li_cmds = []
    _li["details"] = ("", "", 0)
    _sm_core.run_command = lambda r, c, **k: (_li_cmds.append(c),
                                             ("50\n__DU_DONE__", "", 0) if "du -sm" in c else ("", "", 0))[1]
    _sh._looks_installed(_app, NS(), "gmodserver", "gmodserver")
    check("_looks_installed: the du command carries the completion marker",
          any("__DU_DONE__" in c for c in _li_cmds), repr(_li_cmds)[-120:])
finally:
    _sm_core.run_command = _li_orig


# ── the stats endpoint must not persist a status it could not read ──────────────────────────────
# server_live_metrics builds its dict UP FRONT and returns it all-zero when the read produced no
# output, so port_open=False / game_procs=0 is indistinguishable from a real stopped server — and
# /api/server/<id>/stats COMMITTED that as gs.status. `free -b` never fails on a reachable host, so
# ram_total==0 is the sentinel; app.py's _live_run_state guards on it and says it is "deliberately
# the SAME predicate /api/server/<id>/stats uses", while that endpoint did not.
#
# Not cosmetic: _query_server_slots short-circuits on gs.status == "offline" and returns 0 players
# WITHOUT querying, which satisfies the one-shot notify_when_empty ("now has 0 players — safe to
# make changes") and clears the flag, with players still connected.
_p02_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_stats_src = open(os.path.join(_p02_root, "panel", "routes", "api.py"), encoding="utf-8").read()
check("stats endpoint: the all-zero sample is rejected by the ram_total sentinel",
      'm.get("ram_total")' in _stats_src)
check("stats endpoint: ...and an unreadable sample does not reach gs.status",
      "_readable and gs.installed and gs.status not in" in _stats_src)
# game_procs is `ps -u <game user> | wc -l`: the tmux server, a cron update and an install's
# steamcmd all count, so it reported (and PERSISTED) "online" for a server that had never
# started. The status column means "a player could connect" — that is the listening port.
check("stats endpoint: online means the port is listening, not that the user owns a process",
      'status = "online" if m.get("port_open") else "offline"' in _stats_src,
      [l for l in _stats_src.splitlines() if 'status = "online"' in l])
check("stats endpoint: ...and an install in progress is never overwritten",
      '_readable and gs.installed and gs.status not in ("installing", "configuring")' in _stats_src)

# The predicate that decides online/offline must stay the one _live_run_state promises it matches.
import app as _app_mod
_lrs_orig = _app_mod._sm.server_live_metrics
try:
    _lrs = {"m": {}}
    _app_mod._sm.server_live_metrics = lambda r, s=None, p=None, force=False: _lrs["m"]
    _gsx, _rx = NS(short_name="gmodserver", port=27015), NS()

    _lrs["m"] = {"ram_total": 0, "port_open": False, "game_procs": 0}      # the failed sample
    check("_live_run_state: an all-zero sample is 'unknown', not 'stopped'",
          _app_mod._live_run_state(_gsx, _rx) is None)
    _lrs["m"] = {"ram_total": 8 * 10 ** 9, "port_open": False, "game_procs": 0}
    check("_live_run_state: a READ sample with nothing running is False",
          _app_mod._live_run_state(_gsx, _rx) is False)
    _lrs["m"] = {"ram_total": 8 * 10 ** 9, "port_open": True, "game_procs": 0}
    check("_live_run_state: a listening port is True", _app_mod._live_run_state(_gsx, _rx) is True)
    _lrs["m"] = {"ram_total": 8 * 10 ** 9, "port_open": False, "game_procs": 4}
    check("_live_run_state: live processes are True", _app_mod._live_run_state(_gsx, _rx) is True)
finally:
    _app_mod._sm.server_live_metrics = _lrs_orig


# ── a crashed server must not report itself online (panel bug #22) ───────────────────────────────
# LinuxGSM's STARTED means "a tmux session with this name exists" — check_status.sh counts
# `tmux list-sessions`, nothing more. What runs inside that session is usually a WRAPPER
# (srcds_run, hlds_run, a Java launcher) that survives the game binary dying and relaunches it in
# a loop, so a server that crashed — or one whose config stops it booting at all — reports STARTED
# for as long as the box is up. Reproduced on the test host: tmux session and ./srcds_run alive,
# no game process, `details` says STARTED.
#
# That answer was not merely displayed. /api/server/<id> COMMITS it to gs.status, overwriting the
# correct "offline" the monitor had just written from the port scan — so the detail page
# contradicted the dashboard AND won.
from panel.ops.ssh_manager import game as _gsm, _core as _gcore, portscan as _gps

_g_rag, _g_rlp = _gcore.run_as_game_user, _gps._remote_listening_ports
try:
    _g = {"out": "", "ports": set()}
    _gcore.run_as_game_user = lambda *a, **k: (_g["out"], "", 0)
    _gps._remote_listening_ports = lambda r: _g["ports"]
    _srv = NS(short_name="gmodserver", lgsm_name="gmodserver", port=27015)

    _g["out"], _g["ports"] = "Status:  STARTED", {27015, 22}
    check("status: STARTED with the game's port listening is online",
          _gsm.get_server_status(NS(id=1), _srv) == "online")

    # THE BUG: the session is there, the game is not.
    _g["out"], _g["ports"] = "Status:  STARTED", {22}
    check("status: STARTED with nothing listening on the game's port is NOT online",
          _gsm.get_server_status(NS(id=1), _srv) == "offline",
          _gsm.get_server_status(NS(id=1), _srv))

    # ...and a caller that needs to know WHICH kind of not-online this is can ask. Folding the
    # two together is right for "can players connect"; it is wrong for "is there anything to act
    # on", and the deferred restart/stop sweep is the second kind. It read "offline" as "already
    # stopped", cleared the operator's queued request and performed nothing — so a "stop when
    # empty" aimed at a crashed server, the very state this downgrade exists to detect, was
    # silently dropped. So was one that landed in the seconds between a restart and the port
    # binding.
    check("status: ...and the caller can tell a dead session from a live one that isn't serving",
          _gsm.get_server_status(NS(id=1), _srv, distinguish_unresponsive=True) == "unresponsive",
          _gsm.get_server_status(NS(id=1), _srv, distinguish_unresponsive=True))
    check("status: ...while STOPPED still says offline either way",
          _gsm.get_server_status(NS(id=1), NS(short_name="gmodserver", lgsm_name="gmodserver",
                                              port=27015), distinguish_unresponsive=True)
          in ("unresponsive", "offline"))
    check("status: a queued restart/stop SURVIVES an unresponsive server instead of being cleared",
          _gsm.mod_restart_decision("unresponsive", None) == "pending",
          _gsm.mod_restart_decision("unresponsive", None))
    check("status: ...while a genuinely stopped one still clears it, which is what idle is for",
          _gsm.mod_restart_decision("offline", None) == "idle")

    # ...but an unreadable host must never be what downgrades it. None is not an empty set.
    _g["ports"] = None
    check("status: a failed port scan leaves LinuxGSM's answer alone",
          _gsm.get_server_status(NS(id=1), _srv) == "online")
    _gps._remote_listening_ports = lambda r: (_ for _ in ()).throw(RuntimeError("ssh down"))
    check("status: ...and so does a port scan that raises",
          _gsm.get_server_status(NS(id=1), _srv) == "online")
    _gps._remote_listening_ports = lambda r: _g["ports"]

    # A server with no port on record has nothing to confirm against.
    _g["ports"] = {22}
    check("status: a server with no port keeps LinuxGSM's answer",
          _gsm.get_server_status(NS(id=1), NS(short_name="x", lgsm_name="x", port=None)) == "online")

    # STOPPED stays authoritative: no session, no server, whoever holds the port.
    _g["out"], _g["ports"] = "Status:  STOPPED", {27015}
    check("status: STOPPED is offline even when something is on the port",
          _gsm.get_server_status(NS(id=1), _srv) == "offline")

    # The cross-check must not have cost us the ANSI/`ismygameserver.online` handling.
    _g["out"], _g["ports"] = "\x1b[0;31mStatus:\x1b[0m\t\x1b[0;32mSTARTED\x1b[0m", {27015}
    check("status: the Status line is still read through ANSI colour",
          _gsm.get_server_status(NS(id=1), _srv) == "online")
    _g["out"], _g["ports"] = "Check: https://ismygameserver.online/?ip=1.2.3.4", {27015}
    check("status: 'ismygameserver.online' in the blob is still not a status",
          _gsm.get_server_status(NS(id=1), _srv) == "unknown")
finally:
    _gcore.run_as_game_user, _gps._remote_listening_ports = _g_rag, _g_rlp

# ── Minting an API token must cost what the other credential changes on that page cost ────────
# /account/api-token/generate was @login_required and nothing else, while the password change and
# the 2FA switch-off in the same cards both demand the password and a live code. That was the
# wrong way round: what this route hands out is a SECOND credential that outlives the session it
# was minted from. by_api_token matches on the digest and is_active alone — no auth_epoch, so the
# bump that sweeps every session cookie does not reach it and only an explicit revoke_api_token()
# does (account_revoke_sessions and account_change_password each had to be taught to call one);
# no totp_enabled, so it never meets the 2FA gate, which exists only in the /login form flow —
# and bearer requests are CSRF-exempt. So one POST from a borrowed tab turned a minute of someone
# else's session into a key with no IP/UA binding, no second factor and no expiry, which those two
# controls take back only if the victim presses them — and nothing visible went wrong to suggest
# they should. (An earlier draft of this comment said a password change and "sign out everywhere"
# LEAVE IT WORKING, present tense, copied from smoke_test's account of the bug those two routes
# were changed to fix. Both revoke it today and smoke_test asserts both do; the tense was the
# whole claim.)
#
# Driven through the REAL view function on a bare Flask app rather than asserted from the source,
# because the source says "check_password" either way — what has to be true is that no token comes
# back. The route's collaborators are stubbed at panel.routes.auth_routes (the module the closure
# reads its globals from) and restored in the finally; check_password and verify_totp_step are the
# real ones, against a real bcrypt hash and a real TOTP secret.
import flask as _atg_flask                                                          # noqa: E402
import panel.routes.auth_routes as _atg_routes                                      # noqa: E402

_atg_app = _atg_flask.Flask(__name__)
_atg_app.secret_key = "unit-suite"
_atg_app.config["LOGIN_DISABLED"] = True    # @login_required is not what is under test here
_atg_routes.register(_atg_app)
_atg_mint = _atg_app.view_functions.get("account_api_token_generate")
_atg_revoke = _atg_app.view_functions.get("account_api_token_revoke")
check("api token: the mint and revoke views registered (the checks below need them)",
      _atg_mint is not None and _atg_revoke is not None,
      "mint=%r revoke=%r" % (_atg_mint, _atg_revoke))

_atg_pw = "Str0ng!passw0rd"
_atg_hash = hash_password(_atg_pw)
_atg_secret = generate_totp_secret()


class _AtgUser:
    """Just enough User for this route: the columns it reads and the two methods it calls."""

    def __init__(self, totp=False):
        self.username = "tokenholder"
        self.password_hash = _atg_hash
        self.totp_enabled = totp
        self.totp_secret_plain = _atg_secret if totp else None
        self.last_totp_step = 0
        self.minted = 0
        self.revoked = 0
        self._spent_backup = set()

    def _get_current_object(self):
        return self

    def generate_api_token(self):
        self.minted += 1
        return "lgsm_" + "0" * 48

    def revoke_api_token(self):
        self.revoked += 1

    def use_backup_code(self, code):
        if code == "aaaaa-bbbbb" and code not in self._spent_backup:
            self._spent_backup.add(code)
            return True
        return False


_atg_saved = {_k: getattr(_atg_routes, _k) for _k in
              ("current_user", "db", "log_action", "render_template", "flash", "redirect", "url_for")}
try:
    _atg_routes.db = type("_AtgDb", (), {
        "session": type("_AtgSess", (), {"commit": staticmethod(lambda: None)})()})()
    _atg_routes.log_action = lambda *a, **k: None
    _atg_routes.render_template = lambda _t, **kw: "TOKEN:%s" % (kw.get("new_token"),)
    _atg_routes.flash = lambda _m, _c="message": None
    _atg_routes.redirect = lambda _loc: "REDIRECTED"
    _atg_routes.url_for = lambda _ep, **kw: "/" + _ep

    def _atg_post(user, **form):
        """POST the mint form as `user`; returns the rendered body (a redirect means refused)."""
        _atg_routes.current_user = user
        with _atg_app.test_request_context("/account/api-token/generate",
                                           method="POST", data=form):
            return _atg_mint()

    # A FRESH user per case on purpose. Sharing one would make the mint counter cumulative, and
    # then the positive controls below would fail alongside the refusals whenever the gate came
    # off — a test that goes all-red proves only that something moved, not what.
    #
    # No password at all — everything a stolen cookie can manage on its own.
    _atg_u = _AtgUser()
    _atg_body = _atg_post(_atg_u)
    check("api token: a mint with NO password mints nothing",
          _atg_u.minted == 0, "minted=%d body=%r" % (_atg_u.minted, _atg_body))
    _atg_u = _AtgUser()
    _atg_body = _atg_post(_atg_u, password="wrong-password")
    check("api token: ...and a WRONG password mints nothing",
          _atg_u.minted == 0, "minted=%d body=%r" % (_atg_u.minted, _atg_body))
    # Positive control: the gate must not be "refuse everything".
    _atg_u = _AtgUser()
    _atg_body = _atg_post(_atg_u, password=_atg_pw)
    check("api token: the account holder's own password still mints one",
          _atg_u.minted == 1 and "lgsm_" in _atg_body,
          "minted=%d body=%r" % (_atg_u.minted, _atg_body))

    # With 2FA on, the password is not the whole proof — same as account_2fa_disable.
    _atg_t = _AtgUser(totp=True)
    _atg_body = _atg_post(_atg_t, password=_atg_pw)
    check("api token: with 2FA on, the password alone mints nothing",
          _atg_t.minted == 0, "minted=%d body=%r" % (_atg_t.minted, _atg_body))
    _atg_t = _AtgUser(totp=True)
    _atg_body = _atg_post(_atg_t, password=_atg_pw, totp_code="000000")
    check("api token: ...and a wrong authenticator code mints nothing",
          _atg_t.minted == 0, "minted=%d body=%r" % (_atg_t.minted, _atg_body))
    # Positive control again: a real code from the authenticator works.
    _atg_t = _AtgUser(totp=True)
    _atg_code = _pyotp.TOTP(_atg_secret).now()
    _atg_body = _atg_post(_atg_t, password=_atg_pw, totp_code=_atg_code)
    check("api token: ...while a valid authenticator code mints one",
          _atg_t.minted == 1 and "lgsm_" in _atg_body,
          "minted=%d body=%r" % (_atg_t.minted, _atg_body))
    check("api token: ...and the step that code spent is recorded",
          (_atg_t.last_totp_step or 0) > 0, "last_totp_step=%r" % _atg_t.last_totp_step)
    # A TOTP code stays valid for ~90s, so "is it valid" is not enough — the step must be spent.
    # Same user deliberately: the replay is only a replay against the step it already spent.
    _atg_body = _atg_post(_atg_t, password=_atg_pw, totp_code=_atg_code)
    check("api token: REPLAYING that same code mints nothing",
          _atg_t.minted == 1, "minted=%d body=%r" % (_atg_t.minted, _atg_body))
    # Someone who has lost their authenticator is not locked out of their own token.
    _atg_b = _AtgUser(totp=True)
    _atg_body = _atg_post(_atg_b, password=_atg_pw, totp_code="aaaaa-bbbbb")
    check("api token: a one-time backup code mints one too",
          _atg_b.minted == 1 and "lgsm_" in _atg_body,
          "minted=%d body=%r" % (_atg_b.minted, _atg_body))
    _atg_body = _atg_post(_atg_b, password=_atg_pw, totp_code="aaaaa-bbbbb")
    check("api token: ...and that backup code is spent, not reusable",
          _atg_b.minted == 1, "minted=%d body=%r" % (_atg_b.minted, _atg_body))

    # Positive control on the OTHER direction: revoking must stay ungated. Taking a credential
    # away is the safe direction, and a gate there is a reason not to press it in a panic.
    _atg_r = _AtgUser()
    _atg_routes.current_user = _atg_r
    with _atg_app.test_request_context("/account/api-token/revoke", method="POST"):
        _atg_revoke()
    check("api token: revoking one still needs nothing but the session",
          _atg_r.revoked == 1, "revoked=%d" % _atg_r.revoked)
finally:
    for _k, _v in _atg_saved.items():
        setattr(_atg_routes, _k, _v)

# ── ...and what it says when it refuses has to be readable in Spanish and French ──────────────
# base.html hands the browser a catalog and walks the DOM, swapping any text whose exact
# whitespace-collapsed form is a key — so a sentence the catalogs have never heard of stays
# English whatever the user picked, and nothing anywhere fails. The i18n gate in part06 reads
# templates/ and static/js/ only, so a sentence that lives in a ROUTE's source is invisible to it:
# both refusals this gate added shipped untranslated, and the four template strings beside them
# (which that gate does see) were translated in the same change. This one reads the flash calls
# out of the route itself, so the NEXT refusal added here has to be translated too rather than
# quietly joining them.
_atg_mint_src = _totp_ast.parse(
    open(os.path.join(_p02_root, "panel", "routes", "auth_routes.py"), encoding="utf-8").read())
_atg_said = []
for _n in _totp_ast.walk(_atg_mint_src):
    if not (isinstance(_n, _totp_ast.FunctionDef) and _n.name == "account_api_token_generate"):
        continue
    for _c in _totp_ast.walk(_n):
        if (isinstance(_c, _totp_ast.Call)
                and getattr(_c.func, "id", getattr(_c.func, "attr", None)) == "flash"
                and _c.args and isinstance(_c.args[0], _totp_ast.Constant)
                and isinstance(_c.args[0].value, str)):
            _atg_said.append(_c.args[0].value)
# A floor, not an inventory: "every sentence found is translated" is satisfied by finding none,
# which is exactly what a renamed route or a flash built from a variable would produce.
check("api token: the mint's refusal sentences were found to check",
      len(_atg_said) >= 3, "the AST walk found %r" % (_atg_said,))
_atg_untranslated = {}
for _lang in ("es", "fr"):
    _atg_keys = set()
    _atg_dir = os.path.join(_p02_root, "translations", _lang)
    for _f in sorted(os.listdir(_atg_dir)):
        if _f.endswith(".json"):
            _atg_keys |= set(json.load(open(os.path.join(_atg_dir, _f), encoding="utf-8")))
    _atg_untranslated[_lang] = [_s for _s in _atg_said if _s not in _atg_keys]
check("api token: every refusal the mint flashes is in the es and fr catalogs",
      not any(_atg_untranslated.values()),
      "; ".join("%s missing %r" % (_l, _m) for _l, _m in sorted(_atg_untranslated.items()) if _m))
