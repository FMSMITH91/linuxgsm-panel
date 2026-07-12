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
import notifications as N
import system_ops as SO
from app import (password_problem, _int_or, _valid_ip_or_cidr, _whitelisted, _parse_tg_command,
                 _tg_command_arg, _valid_hex_color, _clean_console_text)
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

# ── accent colour (Settings → Branding) is emitted into a CSS custom property, so it MUST be a
#    strict #rrggbb literal — never arbitrary text that could carry `}`/`<` and break out. ──
eq("hex colour: valid passes through (lowercased)", _valid_hex_color("#10B981"), "#10b981")
eq("hex colour: bare 6-hex gets a '#'", _valid_hex_color("1a2b3c"), "#1a2b3c")
eq("hex colour: surrounding whitespace trimmed", _valid_hex_color("  #ABCDEF "), "#abcdef")
eq("hex colour: blank -> '' (use built-in)", _valid_hex_color(""), "")
eq("hex colour: None -> ''", _valid_hex_color(None), "")
eq("hex colour: 3-digit shorthand rejected", _valid_hex_color("#fff"), "")
eq("hex colour: named colour rejected", _valid_hex_color("red"), "")
eq("hex colour: CSS/HTML breakout rejected", _valid_hex_color("#fff;}</style><script>"), "")
eq("hex colour: too long rejected", _valid_hex_color("#1234567"), "")

# ── console cleaning: Minecraft/Paper's JLine console writes ANSI escapes (incl. \x1b[K -> a visible
#    "[K"), carriage returns, and bare "> " prompt lines into its log. Strip them for display; leave
#    plain-text (Source/CoD/GMod) consoles untouched. ──
_mc_raw = ("\x1b[K[02:46:21 INFO]: UUID of player Kitty is abc\n> \n"
           "\x1b[K[02:46:21 INFO]: Connection closed\n> \n")
_mc_clean = _clean_console_text(_mc_raw)
check("console: JLine \\x1b[K erase-line removed (no visible '[K')", "[K" not in _mc_clean)
check("console: bare '> ' prompt lines dropped",
      not any(ln.strip() == ">" for ln in _mc_clean.split("\n")))
check("console: real log lines preserved",
      "[02:46:21 INFO]: UUID of player Kitty is abc" in _mc_clean
      and "[02:46:21 INFO]: Connection closed" in _mc_clean)
eq("console: ANSI colour codes stripped",
   _clean_console_text("\x1b[0;32mgreen\x1b[0m text"), "green text")
eq("console: carriage-return redraw normalised",
   _clean_console_text("first\r\nsecond\rthird"), "first\nsecond\nthird")
eq("console: an echoed command line ('> list') is kept",
   _clean_console_text("> list"), "> list")
eq("console: plain Source/CoD line untouched",
   _clean_console_text("L 01/01/2026 - 12:00: player connected"),
   "L 01/01/2026 - 12:00: player connected")
eq("console: empty input -> empty", _clean_console_text(""), "")

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
# NOTHING is locked any more — every line is editable/deletable, including the panel-installed ones.
check("cron: monitor is NOT managed (editable/deletable)",
      not sm._cron_line_managed("*/5 * * * * /home/gm/gmodserver monitor > /dev/null 2>&1", "gm", "gmodserver"))
check("cron: daily-restart flag is NOT managed (editable/deletable)",
      not sm._cron_line_managed("0 5 * * * touch /home/gm/.restart-pending", "gm", "gmodserver"))
check("cron: legacy @reboot start is NOT managed (deletable)",
      not sm._cron_line_managed("@reboot /home/gm/gmodserver start > /dev/null 2>&1", "gm", "gmodserver"))
check("cron: user backup line is NOT managed",
      not sm._cron_line_managed("0 3 * * * /home/gm/backup.sh", "gm", "gmodserver"))
# _cron_role gives panel lines a non-blocking LABEL so the admin knows what they are.
check("cron role: monitor is labelled 'autostart'",
      sm._cron_role("/home/gm/gmodserver monitor", "gm", "gmodserver") == "autostart")
check("cron role: a .restart-pending line is labelled 'daily-restart'",
      sm._cron_role("[ -f /home/gm/.restart-pending ] && /home/gm/gmodserver restart", "gm", "gmodserver") == "daily-restart")
check("cron role: update / user jobs carry no label",
      sm._cron_role("/home/gm/gmodserver update", "gm", "gmodserver") == ""
      and sm._cron_role("/home/gm/backup.sh", "gm", "gmodserver") == "")
# _wrap_cron_command keeps the monitor marker VISIBLE (inline recorder) so a reschedule doesn't hide it
# from the Autostart detection; the .restart-pending line stays verbatim; a `%` command uses base64.
_wmon = sm._wrap_cron_command(None, "gm", "/home/gm/gmodserver monitor")
check("cron wrap: a plain command (monitor) stays visible, not base64-hidden",
      "/home/gm/gmodserver monitor" in _wmon and ".lgsm-cron/run " not in _wmon)
check("cron wrap: the .restart-pending flag line is kept verbatim",
      sm._wrap_cron_command(None, "gm", "[ -f /home/gm/.restart-pending ] && x")
      == "[ -f /home/gm/.restart-pending ] && x")
_orig_wrap_rc = sm.run_command
try:
    sm.run_command = lambda *a, **k: ("", "", 0)   # _install_cron_runner touches SSH on the base64 path
    _wpct = sm._wrap_cron_command(None, "gm", "echo %H")
    check("cron wrap: a '%' command uses the base64 runner (cron-safe)",
          ".lgsm-cron/run " in _wpct and "%H" not in _wpct)
finally:
    sm.run_command = _orig_wrap_rc

# node-tools auto-update: a weekly ROOT cron keeps npm + gamedig (player-query tools) current.
check("node-tools: the cron updates npm + gamedig weekly and logs it",
      "npm install -g npm gamedig" in sm._NODE_TOOLS_CRON
      and sm._NODE_TOOLS_CRON.lstrip().startswith("#")
      and "/var/log/lgsm-node-tools.log" in sm._NODE_TOOLS_CRON
      and sm._NODE_TOOLS_CRON_PATH == "/etc/cron.d/lgsm-node-tools")
_ntc = {}
_orig_ntc_rc = sm.run_command
try:
    sm.run_command = lambda s, c, **k: (_ntc.__setitem__("cmd", c), ("", "", 0))[1]
    _ntc_ok = sm.ensure_node_tools_cron(object())
    check("node-tools: ensure writes the cron.d file as ROOT (sudo bash -c)",
          _ntc_ok is True and _ntc["cmd"].startswith("sudo bash -c")
          and "/etc/cron.d/lgsm-node-tools" in _ntc["cmd"])
    check("node-tools: the cron body is base64-piped + chmod 644 (no quoting/`%` hazards)",
          "base64 -d" in _ntc["cmd"] and "chmod 644" in _ntc["cmd"])
finally:
    sm.run_command = _orig_ntc_rc

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

# ── apt dependency names parsed from LinuxGSM output get interpolated into
#    `apt-get install <pkgs>`, so parse_missing_deps is a security filter, not just a parser. ──
eq("parse_missing_deps: extracts valid package names",
   sm.parse_missing_deps("log line\nMissing dependencies: libssl-dev lib32gcc-s1 gcc:i386  Run: x\n"),
   ["libssl-dev", "lib32gcc-s1", "gcc:i386"])
eq("parse_missing_deps: drops shell-metachar tokens (injection guard)",
   sm.parse_missing_deps("Missing dependencies: good $(reboot) a;b `id` also-good\n"),
   ["good", "also-good"])
eq("parse_missing_deps: no marker -> []", sm.parse_missing_deps("nothing to see here"), [])

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
   sm._valid_content_games(["cstrike", "doom", "cstrike"]), ["cstrike"])
eq("gmod content: empty -> []", sm._valid_content_games([]), [])
_gmc, _gmd = sm._gmod_mount_files("srcds", ["cstrike"])
check("gmod content: mount.cfg points cstrike at the content user's serverfiles",
      _gmc.startswith('"mountcfg"') and '"cstrike"\t"/home/srcds/serverfiles/cstrike"' in _gmc)
check("gmod content: mountdepots enables hl2 + cstrike",
      _gmd.startswith('"gamedepotsystem"') and '"hl2"' in _gmd and '"cstrike"' in _gmd)
# detect_content_user: parse a host scan, reject non-username tokens, resolve the primary group.
_orig_gm_rc = sm.run_command
try:
    def _gm_fake(server, cmd, **k):
        if "for u in" in cmd:
            return "HIT|srcds|cstrike\nHIT|b@d|cstrike\nHIT|srcds|cstrike", "", 0
        if "id -gn" in cmd:
            return "srcds", "", 0
        return "", "", 0
    sm.run_command = _gm_fake
    _det = sm.detect_content_user(object(), ("cstrike",))
    check("gmod content: detect reuses a valid content user, rejects bad usernames",
          bool(_det) and _det["user"] == "srcds" and _det["group"] == "srcds"
          and _det["present"].get("cstrike") == "/home/srcds/serverfiles/cstrike")
finally:
    sm.run_command = _orig_gm_rc

# a bad schedule is rejected by update before any SSH
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
# Maintenance + autostart jobs use the INLINE recorder: the command stays visible (so the grep-based
# dedup/removal + last-run detection still work) and unwraps to the core command + a job id.
_mrec = sm._record_managed_cmd("gm", "/home/gm/gmodserver update")
check("managed cron: inline-recorded maintenance line still matches the dedup remove-regex",
      bool(__import__("re").search(r"/home/gm/gmodserver (monitor|mods-update|update|update-lgsm) ", _mrec)))
check("managed cron: unwrap recovers the core command + id",
      sm._unwrap_cron_command(_mrec)
      == ("/home/gm/gmodserver update", sm._cron_job_id("/home/gm/gmodserver update")))
# Nothing is managed now: an inline-recorded line (even monitor) is editable/deletable — the role
# label is all that distinguishes a panel line.
check("cron: an inline-recorded maintenance line is not managed (editable/deletable)",
      not sm._cron_line_managed(_mrec, "gm", "gmodserver"))
check("cron: an inline-recorded monitor line is not managed either — just role-labelled 'autostart'",
      not sm._cron_line_managed(sm._record_managed_cmd("gm", "/home/gm/gmodserver monitor"), "gm", "gmodserver")
      and sm._cron_role("/home/gm/gmodserver monitor", "gm", "gmodserver") == "autostart")
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
    _bk.remove_game_schedule(77)   # must not raise on a corrupted map
    check("schedule: remove_game_schedule is a safe no-op on junk", True)
finally:
    _bk.load_config, _bk.update_config = _sched_load, _sched_update

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

# _dedupe_aux_ports: a 2nd Source server must move its SourceTV/client ports off any already taken,
# so -strictportbind doesn't quit it. Free ports keep their value (and are omitted from the result).
from app import _dedupe_aux_ports
eq("aux-ports: both free -> no changes",
   _dedupe_aux_ports({"clientport": 27005, "sourcetvport": 27020}, {27015}), {})
eq("aux-ports: both taken -> each bumped to the next free port",
   _dedupe_aux_ports({"clientport": 27005, "sourcetvport": 27020}, {27005, 27015, 27020}),
   {"clientport": 27006, "sourcetvport": 27021})
eq("aux-ports: only the colliding key moves",
   _dedupe_aux_ports({"clientport": 27005, "sourcetvport": 27020}, {27020}),
   {"sourcetvport": 27021})
eq("aux-ports: scans past a run of taken ports",
   _dedupe_aux_ports({"sourcetvport": 27020}, {27020, 27021, 27022}), {"sourcetvport": 27023})
eq("aux-ports: two keys never land on the same freed port",
   _dedupe_aux_ports({"clientport": 27020, "sourcetvport": 27020}, {27020}),
   {"clientport": 27021, "sourcetvport": 27022})

# _extract_start_error: turn a game's start log into a one-line reason (or "" if none is clear), so a
# failed auto-start shows WHY instead of a bare "offline".
from app import _extract_start_error
eq("start-error: pulls the -strictportbind port line, ANSI stripped",
   _extract_start_error('boot\n\x1b[38;2;255;90;90mERROR: Port 27020 was unavailable - quitting due to "-strictportbind" flag!\x1b[39m\nmore'),
   'Port 27020 was unavailable - quitting due to "-strictportbind" flag!')
eq("start-error: a clean boot log yields no reason", _extract_start_error("Loading map\nServer started"), "")
eq("start-error: catches a couldn't-load line", _extract_start_error("Couldn't open mapcycle.txt"),
   "Couldn't open mapcycle.txt")
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

# REGRESSION: Tailscale up WITH a MagicDNS name but Serve NOT configured must NOT bind to loopback
# (that hid the panel on 127.0.0.1 with nothing proxying to it — a fresh install was unreachable).
from tailscale_integration import TailscaleInfo   # noqa: E402
_orig_gti = _tsi.get_tailscale_info
try:
    _tsi.get_tailscale_info = lambda *a, **k: TailscaleInfo(
        installed=True, running=True, backend_state="Running", tailscale_ips=["100.90.141.12"],
        dns_name="host.example.ts.net", serve_config={"services": [], "raw": "No serve config"})
    _tsi._cache["info"] = None
    _bns = _tsi.suggest_best_bind(5000)
    check("tailscale: up + DNS name but Serve NOT set up -> does NOT bind loopback",
          _bns["bind_host"] != "127.0.0.1")
    _tsi.get_tailscale_info = lambda *a, **k: TailscaleInfo(
        installed=True, running=True, backend_state="Running", tailscale_ips=["100.90.141.12"],
        dns_name="host.example.ts.net",
        serve_config={"services": [{"url": "https://host.example.ts.net", "routes": [{}]}], "raw": "x"})
    _tsi._cache["info"] = None
    _bys = _tsi.suggest_best_bind(5000)
    check("tailscale: up + DNS name + Serve configured -> binds loopback for Serve",
          _bys["bind_host"] == "127.0.0.1" and _bys["method"] == "tailscale-serve")
finally:
    _tsi.get_tailscale_info = _orig_gti
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
# REGRESSION: LinuxGSM lists an 'Installed addons/mods' section (bare ' * <id>' lines, no
# description) BEFORE 'Available addons/mods'. Those bare ids must NOT be emitted as phantom mods
# named after the section header, nor duplicate the real Available rows (bug: ulib/ulx showed twice).
_mods_avail_full = (
    "Garry's Mod Installing Mods\n"
    "=================================\n"
    "Installed addons/mods\n"
    "=================================\n"
    " * ulib\n"
    " * ulx\n"
    "\n"
    "Available addons/mods\n"
    "=================================\n"
    "Metamod: Source - Plugins Framework - https://www.sourcemm.net\n"
    " * metamodsource\n"
    "ULib - Complete Framework - http://ulyssesmod.net\n"
    " * ulib\n"
    "ULX - Admin Panel (requires ULib) - http://ulyssesmod.net\n"
    " * ulx\n"
    "Enter an addon/mod to install (or exit to abort):\n"
)
_avf = sm._parse_mods_available(_mods_avail_full)
_avf_ids = [m["id"] for m in _avf]
check("mods: the 'Installed addons/mods' section is not emitted as phantom entries",
      not any(m["name"].lower() == "installed addons/mods" for m in _avf))
check("mods: each available id appears exactly once (ulib/ulx not duplicated)",
      _avf_ids == ["metamodsource", "ulib", "ulx"])
check("mods: the deduped ulib/ulx keep their real names, not the section header",
      {m["id"]: m["name"] for m in _avf}.get("ulib") == "ULib"
      and {m["id"]: m["name"] for m in _avf}.get("ulx") == "ULX")
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

# ── list_server_commands: parse LinuxGSM's command menu. This is what populates the
#    "Supported Commands" panel; import now auto-caches it in the background, so lock in
#    that a realistic menu (with ANSI colour + non-menu noise lines) parses correctly. ──
_LGSM_MENU = (
    "\x1b[0m./gmodserver [option]\n"
    "start         st   | Start the server.\n"
    "stop          sp   | Stop the server.\n"
    "update        u    | Check and apply any updates.\n"
    "some banner line without a pipe here\n"
    "details       dt   | Display server information.\n"
)
_saved_run = sm.run_command
try:
    sm.run_command = lambda *a, **k: (_LGSM_MENU, "", 0)
    _parsed = sm.list_server_commands(NS(), "gmodserver")
finally:
    sm.run_command = _saved_run
_pc = {c["cmd"]: c for c in _parsed}
check("list_server_commands: parses start (with short code)",
      _pc.get("start", {}).get("short") == "st")
check("list_server_commands: parses update", "update" in _pc)
eq("list_server_commands: captures description", _pc.get("details", {}).get("desc"),
   "Display server information.")
check("list_server_commands: ignores the ./script header + no-pipe banner lines",
      "some" not in _pc and "gmodserver" not in _pc and len(_pc) == 4)

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

# _gamedig_host: Source servers reply to A2S from the host's real IP, so a 127.0.0.1 query is
# silently dropped — the panel must query the host's primary IP. (run_command runs the awk pipeline
# remotely, so the stub returns what awk WOULD emit: just the IP, or nothing.)
class _FakeRemote:
    def __init__(self, rid): self.id = rid
_orig_rc = sm.run_command
try:
    sm._gamedig_host_cache.clear()
    sm.run_command = lambda *a, **k: ("45.76.63.211\n", "", 0)
    check("gamedig-host: uses the host's primary IP, not 127.0.0.1",
          sm._gamedig_host(_FakeRemote(9001)) == "45.76.63.211")
    sm._gamedig_host_cache.clear()
    sm.run_command = lambda *a, **k: ("", "", 0)          # no default route / no output
    check("gamedig-host: falls back to 127.0.0.1 when the IP can't be resolved",
          sm._gamedig_host(_FakeRemote(9002)) == "127.0.0.1")
    sm._gamedig_host_cache.clear()
    _calls = {"n": 0}
    def _counting_rc(*a, **k):
        _calls["n"] += 1
        return ("10.0.0.5\n", "", 0)
    sm.run_command = _counting_rc
    _r = _FakeRemote(9003)
    sm._gamedig_host(_r); sm._gamedig_host(_r)
    check("gamedig-host: caches per remote (one lookup, not one per query)", _calls["n"] == 1)
finally:
    sm.run_command = _orig_rc
    sm._gamedig_host_cache.clear()

# _tmux_live_socket_sh: LinuxGSM leaves a stale <selfname>-<random> socket behind on every restart,
# so the console targeting must pick the socket with a LIVE session (via has-session) rather than the
# first match — otherwise send-keys/capture-pane hit a dead socket and kick/ban/say/status all no-op.
_snip = sm._tmux_live_socket_sh("gmodserver")
check("tmux-socket: verifies a live session instead of grabbing the first socket",
      "has-session -t gmodserver" in _snip and "grep -m1" not in _snip)
check("tmux-socket: still signals NO_SESSION when nothing is live",
      "NO_SESSION" in _snip and "exit 3" in _snip)

# ensure_persistent_bans: a banid ban only survives a restart if the server config execs
# banned_user.cfg — this appends that (idempotently) to the resolved servercfg (${selfname}.cfg).
_orig_lgv2, _orig_rc3 = sm.lgsm_get_values, sm.run_command
try:
    sm.lgsm_get_values = lambda *a, **k: {"servercfg": "${selfname}.cfg"}
    _pb = {}
    sm.run_command = lambda server, cmd, timeout=15, sudo=False: (_pb.__setitem__("cmd", cmd), ("", "", 0))[1]
    _ok_pb = sm.ensure_persistent_bans(object(), "gmodserver2", "gmodserver")
    check("persistent-bans: targets the resolved servercfg, adds the exec, guards duplicates",
          _ok_pb is True and "*/cfg/gmodserver.cfg" in _pb["cmd"]
          and "exec banned_user.cfg" in _pb["cmd"] and "grep -qiE" in _pb["cmd"])
finally:
    sm.lgsm_get_values, sm.run_command = _orig_lgv2, _orig_rc3

# game_map: a separate cached gamedig read for the current map, kept out of the player-count path.
_orig_rc5 = sm.run_command
try:
    sm._game_map_cache.clear(); sm.run_command = lambda *a, **k: ("de_dust2\n", "", 0)
    check("game-map: parses the map name from gamedig", sm.game_map(object(), "u", "css", 27015) == "de_dust2")
    sm._game_map_cache.clear(); sm.run_command = lambda *a, **k: ("null\n", "", 0)
    check("game-map: 'null'/empty gamedig output -> ''", sm.game_map(object(), "u", "css", 27015) == "")
    sm._game_map_cache.clear(); sm.run_command = lambda *a, **k: ("<b>gm_x\n", "", 0)
    check("game-map: strips angle brackets from game-supplied text",
          "<" not in sm.game_map(object(), "u", "css", 27015) and ">" not in sm.game_map(object(), "u", "css", 27015))
    check("game-map: no gamedig type/port -> '' (no query)", sm.game_map(object(), "u", "css", None) == "")
finally:
    sm.run_command = _orig_rc5; sm._game_map_cache.clear()

# player_list: gamedig is PRIMARY (no console spam). The console is a backup used ONLY when the
# caller explicitly passes allow_console=True (a user action) — the automatic path (default) never
# touches the console: it returns None ('unknown') so the UI shows a GSLT hint instead of querying.
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
    check("player_list: the automatic path is gamedig-only — no console, returns None when unread",
          sm.player_list(None, "u", "cod", 28960, None, "codserver") is None)
    check("player_list: the console backup runs ONLY when allow_console=True (an explicit action)",
          [p["name"] for p in sm.player_list(None, "u", "cod", 28960, None, "codserver",
                                             allow_console=True)] == ["Ace"])
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
    check("moderation: valve ban bans + kicks the re-validated SteamID only (injection stripped)",
          _msent.get("cmd") == "banid 0 STEAM_0:1:5 kick; writeid")
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
          _msent.get("cmd") == "banid 0 STEAM_0:1:9 kick; writeid")
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

# ── Notifications: SSRF guards, provider validation, and event-key wiring ──
import pathlib as _pl   # noqa: E402
import re as _re        # noqa: E402

# Discord webhook is rebuilt onto a CONSTANT host from a validated id/token (no user-controlled host).
check("notify: valid discord webhook is accepted + kept on discord.com",
      N._discord_api_url("https://discord.com/api/webhooks/123456789012/AbC-dEf_ghIJKLmnop")
      == "https://discord.com/api/webhooks/123456789012/AbC-dEf_ghIJKLmnop")
check("notify: discordapp.com webhook is canonicalised to discord.com",
      N._discord_api_url("https://discordapp.com/api/webhooks/123456789012/tok_ABCdef")
      == "https://discord.com/api/webhooks/123456789012/tok_ABCdef")
check("notify: SSRF - an internal host is rejected",
      N._discord_api_url("https://169.254.169.254/api/webhooks/123456789012/x") is None)
check("notify: SSRF - a non-webhook discord path is rejected",
      N._discord_api_url("https://discord.com/evil") is None)
check("notify: SSRF - _post refuses a non-allow-listed host",
      N._post("https://evil.example.com/x", b"", {}) == (False, "blocked"))
check("notify: SSRF - _post refuses a non-https URL",
      N._post("http://api.telegram.org/botX/sendMessage", b"", {})[0] is False)
# Telegram token/chat validation short-circuits before any network call.
check("notify: telegram rejects a malformed bot token",
      N.send_telegram("not-a-real-token", "123456", "hi")[0] is False)
check("notify: telegram rejects an empty chat id",
      N.send_telegram("123456:AAABBBCCCDDDEEEFFF_gg-hh", "", "hi")[0] is False)
# EVENTS registry shape, and every notify() call in app.py uses a registered key (a typo'd key would
# silently never fire — like a data-action with no handler).
check("notify: EVENTS entries are (label:str, default:bool)",
      all(isinstance(v, tuple) and len(v) == 2 and isinstance(v[0], str) and isinstance(v[1], bool)
          for v in N.EVENTS.values()))
_app_src = (_pl.Path(__file__).resolve().parent.parent / "app.py").read_text(encoding="utf-8")
_used_keys = set(_re.findall(r'notifications\.notify\(\s*"(\w+)"', _app_src))
check("notify: every notify() key in app.py is registered in EVENTS",
      _used_keys and _used_keys <= set(N.EVENTS), "unregistered: %s" % sorted(_used_keys - set(N.EVENTS)))

# The global 'enabled' master switch was removed (a channel's own toggle is the on/off). The one-time
# migration must PRESERVE a previously-muted state: master off -> disable both channels, then drop the
# key — otherwise removing the gate would silently start sending to still-enabled channels.
_m_off = {"enabled": False, "telegram": {"enabled": True}, "discord": {"enabled": True}}
check("master-switch drop: was off -> both channels disabled + key removed",
      N._drop_master_switch(_m_off) is True and "enabled" not in _m_off
      and _m_off["telegram"]["enabled"] is False and _m_off["discord"]["enabled"] is False)
_m_on = {"enabled": True, "telegram": {"enabled": True}, "discord": {"enabled": False}}
check("master-switch drop: was on -> channels untouched, key removed",
      N._drop_master_switch(_m_on) is True and "enabled" not in _m_on
      and _m_on["telegram"]["enabled"] is True and _m_on["discord"]["enabled"] is False)
_m_none = {"telegram": {"enabled": True}}
check("master-switch drop: already migrated (no key) -> no change",
      N._drop_master_switch(_m_none) is False and _m_none == {"telegram": {"enabled": True}})

# Alert thresholds: disk %/mem % are real percents (<=99); CPU 'load' is a per-core loadavg % that can
# exceed 100; load_mins is the sustained window. Each is clamped to its own range with defaults.
_orig_thr_cfg = N._cfg
try:
    N._cfg = lambda: {}
    check("thresholds: sensible defaults when unset",
          N.get_thresholds() == {"disk_pct": 90, "load_pct": 200, "mem_pct": 90, "load_mins": 5})
    N._cfg = lambda: {"thresholds": {"disk_pct": 250, "mem_pct": 250, "load_pct": 250, "load_mins": 999}}
    _thi = N.get_thresholds()
    check("thresholds: disk % and mem % are capped at 99 (real percentages)",
          _thi["disk_pct"] == 99 and _thi["mem_pct"] == 99)
    check("thresholds: CPU load may exceed 100% (loadavg-based, ceiling 800)", _thi["load_pct"] == 250)
    check("thresholds: the sustained-minutes window is capped at 120", _thi["load_mins"] == 120)
    N._cfg = lambda: {"thresholds": {"load_pct": 5, "load_mins": 0}}
    _thlo = N.get_thresholds()
    check("thresholds: values below the floor clamp up (load>=50, mins>=1)",
          _thlo["load_pct"] == 50 and _thlo["load_mins"] == 1)
finally:
    N._cfg = _orig_thr_cfg
# The monitor's sustained window maps minutes -> consecutive passes at the 60s monitor cadence.
import app as _app_thr  # noqa: E402
check("thresholds: 60s monitor cadence means load_mins == required consecutive passes",
      _app_thr._MONITOR_SECONDS == 60 and max(1, round(10 * 60 / _app_thr._MONITOR_SECONDS)) == 10)

# ── Login-security whitelist + auto-block threshold ──
import ipaddress as _ipaddr  # noqa: E402

check("whitelist: a bare IP is accepted + canonicalised", _valid_ip_or_cidr("  1.2.3.4 ") == "1.2.3.4")
check("whitelist: a CIDR is accepted + canonicalised to its network", _valid_ip_or_cidr("10.0.0.5/24") == "10.0.0.0/24")
check("whitelist: junk / empty is rejected", _valid_ip_or_cidr("not-an-ip") is None and _valid_ip_or_cidr("") is None)
check("whitelist: an out-of-range octet is rejected", _valid_ip_or_cidr("999.1.1.1") is None)
_wl_nets = [_ipaddr.ip_network("10.0.0.0/8"), _ipaddr.ip_network("203.0.113.7")]
check("whitelist: a CIDR entry covers an address inside it", _whitelisted("10.1.2.3", _wl_nets) is True)
check("whitelist: an exact-IP entry matches that IP", _whitelisted("203.0.113.7", _wl_nets) is True)
check("whitelist: an address outside every entry does not match", _whitelisted("8.8.8.8", _wl_nets) is False)
check("whitelist: a non-IP string never matches", _whitelisted("garbage", _wl_nets) is False)

# The fail2ban ignoreip line is built ONLY from entries that re-parse as an IP/CIDR — defence-in-depth
# so no attacker-influenced token can ever be written into the root-owned jail file.
_ign = SO._f2b_ignoreip_line(["1.2.3.4", "10.0.0.0/8", "evil; rm -rf /", "$(whoami)", "not-an-ip"])
check("f2b: ignoreip always includes localhost", "127.0.0.1/8" in _ign and "::1" in _ign)
check("f2b: ignoreip keeps the valid IP + CIDR entries", "1.2.3.4" in _ign and "10.0.0.0/8" in _ign)
check("f2b: ignoreip drops every non-IP token (no shell metachars reach the jail file)",
      not any(bad in _ign for bad in (";", "$", "rm", "whoami", "not-an-ip")))
_jail = SO._panel_f2b_jail_body("/data/auth.log", 5000, ["1.2.3.4", "junk"])
check("f2b: the jail body carries an ignoreip line with the valid entry only",
      "\nignoreip = " in _jail and "1.2.3.4" in _jail and "junk" not in _jail)

# top-offenders parsing: the counting pipeline emits "<attempts>\t<bans>\t<ip>\t<jail,jail>"; each row
# must surface which fail2ban jail(s) caught the IP. Old 3-field lines (no jail) parse with jails=[].
_top = SO._parse_top_ips("9\t3\t1.2.3.4\tsshd,recidive\n5\t0\t5.6.7.8\tpanel-login\n2\t0\t9.9.9.9",
                         banned_now={"1.2.3.4"}, blocked={"5.6.7.8": "panel-block"})
check("f2b top: attempts/bans/ip parse in order",
      [(r["ip"], r["attempts"], r["bans"]) for r in _top]
      == [("1.2.3.4", 9, 3), ("5.6.7.8", 5, 0), ("9.9.9.9", 2, 0)])
check("f2b top: the jail column surfaces every jail that caught the IP",
      _top[0]["jails"] == ["sshd", "recidive"] and _top[1]["jails"] == ["panel-login"])
check("f2b top: a legacy 3-field line (no jail) parses with an empty jail list",
      _top[2]["jails"] == [])
check("f2b top: banned_now / blocked flags still track the passed-in sets",
      _top[0]["banned_now"] is True and _top[1]["blocked"] is True and _top[2]["blocked"] is False)

# Telegram command parsing: normalise '/Cmd@Bot arg' to a bare lowercase verb; non-commands -> ''.
check("telegram: /update parses to 'update'", _parse_tg_command("/update") == "update")
check("telegram: a bot-mention + args is stripped", _parse_tg_command("/Update@MyBot now") == "update")
check("telegram: /STATUS is lowercased", _parse_tg_command("/STATUS") == "status")
check("telegram: a non-command is empty", _parse_tg_command("hello there") == "" and _parse_tg_command("") == "")
check("telegram: /restart <name> extracts the argument", _tg_command_arg("/restart my server") == "my server")
check("telegram: a bare command has no argument", _tg_command_arg("/status") == "")

# telegram_set_commands registers the '/' autocomplete menu via setMyCommands (through _post).
import json as _json_tg  # noqa: E402
_tg_posts = []
_orig_post = N._post
try:
    N._post = lambda url, data, headers: (_tg_posts.append((url, data)), (True, "sent"))[1]
    check("telegram: set_commands posts to setMyCommands with the registered command set",
          N.telegram_set_commands("123456:AAABBBCCCDDDEEEFFF_gg-hh")
          and _tg_posts[-1][0].endswith("/setMyCommands")
          and {c["command"] for c in _json_tg.loads(_tg_posts[-1][1].decode())["commands"]}
          == {c for c, _ in N.TG_COMMANDS})
    N.telegram_set_commands("123456:AAABBBCCCDDDEEEFFF_gg-hh", clear=True)
    check("telegram: set_commands(clear=True) sends an empty command list",
          _json_tg.loads(_tg_posts[-1][1].decode())["commands"] == [])
    check("telegram: set_commands rejects a malformed token", N.telegram_set_commands("nope") is False)
finally:
    N._post = _orig_post

# ── Discord command bot (Gateway): parsing, SSRF-safe reply path, and the message pump ──
from app import _parse_dc_command  # noqa: E402

# Command parsing accepts either '!' (types cleanly — Discord reserves '/') or '/'; mention + args stripped.
check("discord: !status parses to 'status'", _parse_dc_command("!status") == "status")
check("discord: a '/' prefix also parses", _parse_dc_command("/restart foo") == "restart")
check("discord: a bot-mention + args is stripped + lowercased", _parse_dc_command("!Restart@bot Now") == "restart")
check("discord: a non-command / bare prefix is empty",
      _parse_dc_command("hello") == "" and _parse_dc_command("! ") == "" and _parse_dc_command("") == "")

# The bot reply URL is rebuilt onto the CONSTANT discord.com host with a digits-only channel id, and the
# same _ALLOWED_PREFIXES barrier that guards the webhook sender now also covers the /channels/ API.
check("discord: bot message URL is built on the constant host from a snowflake channel id",
      N._discord_bot_message_url("112233445566778899")
      == "https://discord.com/api/v10/channels/112233445566778899/messages")
check("discord: SSRF - a non-numeric / traversal channel id is rejected",
      N._discord_bot_message_url("../evil") is None and N._discord_bot_message_url("") is None)
check("discord: SSRF - the bot channels URL sits on an allow-listed prefix",
      "https://discord.com/api/v10/channels/1/messages".startswith(N._ALLOWED_PREFIXES))
check("discord: SSRF - a discord.com look-alike host is not allow-listed",
      not "https://discord.com.evil.example/api/x".startswith(N._ALLOWED_PREFIXES))

# The bot token only ever rides in an Authorization header — the charset forbids whitespace/newlines so
# it can't inject one, and it's loose on the internal '.'-separated shape so future formats still pass.
# A dotted, real-shaped fixture that is deliberately NOT a valid Discord token layout (lowercase, wrong
# segment lengths) so GitHub push-protection doesn't flag it — it only needs to exercise the charset.
check("discord: a plausible bot token validates",
      N._valid_discord_bot_token("panel.fixture.not_a_real_token_" + "a" * 30))
check("discord: a bot token with a space is rejected", not N._valid_discord_bot_token("has a space " + "x" * 40))
check("discord: a bot token with a newline (header injection) is rejected",
      not N._valid_discord_bot_token("tok\nX-Evil: 1 " + "x" * 40))

# discord_bot_send validates BEFORE any network call, and posts to the constant host with a Bot header.
_dc_posts = []
_orig_post2 = N._post
try:
    N._post = lambda url, data, headers: (_dc_posts.append((url, headers)), (True, "sent"))[1]
    _ok_send, _ = N.discord_bot_send("A" * 50, "112233445566778899", "hi")
    check("discord: a bot reply posts to the constant discord.com channels API",
          _ok_send and _dc_posts[-1][0] == "https://discord.com/api/v10/channels/112233445566778899/messages")
    check("discord: a bot reply carries an 'Authorization: Bot' header",
          _dc_posts[-1][1].get("Authorization", "").startswith("Bot "))
    check("discord: bot send rejects a malformed channel id without a network call",
          N.discord_bot_send("A" * 50, "../evil", "hi")[0] is False)
    check("discord: bot send rejects a malformed token without a network call",
          N.discord_bot_send("bad token", "112233445566778899", "hi")[0] is False)
finally:
    N._post = _orig_post2


# The Gateway pump: HELLO -> IDENTIFY (with the message-content intent) -> deliver MESSAGE_CREATE to the
# handler -> return on EOF. A fake socket stands in for the WebSocket so no network is touched.
class _FakeWS:
    def __init__(self, frames):
        self._frames = list(frames)
        self.sent = []
    def recv(self):
        return self._frames.pop(0) if self._frames else ""   # "" == EOF -> the loop breaks
    def send(self, s):
        self.sent.append(s)
    def close(self):
        pass


_dc_seen = []
_fake_ws = _FakeWS([
    '{"op":10,"d":{"heartbeat_interval":600000}}',
    '{"op":0,"s":1,"t":"MESSAGE_CREATE","d":{"channel_id":"999","author":{"bot":false},"content":"!status"}}',
])
N.discord_gateway_run("A" * 50, lambda ch, is_bot, content: _dc_seen.append((ch, is_bot, content)),
                      _connect=lambda: _fake_ws)
check("discord: the gateway IDENTIFYs with the message-content intent",
      any('"op": 2' in s and str(N._DISCORD_INTENTS) in s for s in _fake_ws.sent))
check("discord: a MESSAGE_CREATE is delivered to the handler with (channel, is_bot, content)",
      _dc_seen == [("999", False, "!status")])
check("discord: the message-content intent bit (1<<15) is set", N._DISCORD_INTENTS & (1 << 15))

# player_slots parses gamedig's compact JSON into (count, max, name); a name with spaces/quotes
# round-trips and junk output is rejected. run_command is stubbed so no SSH/gamedig is needed.
_orig_rc = sm.run_command
try:
    sm.run_command = lambda *a, **k: ('{"c":7,"m":24,"n":"[EU] Bob\'s \\"Fun\\" Server","ok":true}', "", 0)
    check("player_slots: parses count/max/name from gamedig JSON",
          sm.player_slots(object(), "u", game_type="csgo", port=27015, query_type="csgo")
          == (7, 24, "[EU] Bob's \"Fun\" Server"))
    sm.run_command = lambda *a, **k: ('{"c":0,"m":null,"n":"","ok":true}', "", 0)
    check("player_slots: null max + empty name -> (0, None, None)",
          sm.player_slots(object(), "u", game_type="csgo", port=27015, query_type="csgo") == (0, None, None))
    # A gamedig FAILURE ({"error":...} -> ok=false) is 'unknown', NOT 0 players, so the caller can
    # fall back to the console instead of showing a bogus 0.
    sm.run_command = lambda *a, **k: ('{"c":0,"m":null,"n":"","ok":false}', "", 0)
    check("player_slots: a failed query (ok=false) -> (None, None, None), not a fake 0",
          sm.player_slots(object(), "u", game_type="csgo", port=27015, query_type="csgo") == (None, None, None))
    sm.run_command = lambda *a, **k: ("not json", "", 0)
    check("player_slots: junk output -> (None, None, None)",
          sm.player_slots(object(), "u", game_type="csgo", port=27015, query_type="csgo") == (None, None, None))
finally:
    sm.run_command = _orig_rc

# Global ban: console_steamid_ban builds the right native ban/unban command from a VALIDATED SteamID,
# and refuses junk before anything reaches the console (send_console_command is stubbed to record it).
_gb_cmds = []
_orig_scc = sm.send_console_command
try:
    sm.send_console_command = lambda server, user, command, timeout=20, selfname=None: (_gb_cmds.append(command), ("", "", 0))[1]
    _ok, _reason = sm.console_steamid_ban(object(), "u", "csgoserver", "STEAM_0:1:5")
    check("global-ban: ban builds 'banid 0 <id> kick; writeid'",
          _ok and _gb_cmds[-1] == "banid 0 STEAM_0:1:5 kick; writeid")
    sm.console_steamid_ban(object(), "u", "csgoserver", "[U:1:11]", unban=True)
    check("global-ban: unban builds 'removeid <id>; writeid'", _gb_cmds[-1] == "removeid [U:1:11]; writeid")
    check("global-ban: an invalid SteamID is rejected before the console",
          sm.console_steamid_ban(object(), "u", "s", "garbage; rm -rf") == (False, "invalid"))
finally:
    sm.send_console_command = _orig_scc

# The REMOTE ignoreip drop-in (pushed to remotes over SSH) is built from the same validated entries.
_dropin = sm._f2b_dropin_ignoreip_body(["9.9.9.9", "10.0.0.0/8", "bad; rm -rf /"])
check("remote-f2b: drop-in is a [DEFAULT] ignoreip block including localhost",
      "[DEFAULT]" in _dropin and "ignoreip = " in _dropin and "127.0.0.1/8" in _dropin)
check("remote-f2b: drop-in keeps the valid IP + CIDR entries", "9.9.9.9" in _dropin and "10.0.0.0/8" in _dropin)
check("remote-f2b: drop-in drops non-IP tokens (no shell metachars in the file)",
      not any(bad in _dropin for bad in (";", "$", "rm", "bad")))

passed = sum(1 for ok, _, _ in results if ok)
for ok, name, detail in results:
    line = ("PASS" if ok else "FAIL") + "  " + name
    if detail and not ok:
        line += "   [%s]" % detail
    print(line)
print("\n%d / %d checks passed" % (passed, len(results)))
sys.exit(0 if results and passed == len(results) else 1)
