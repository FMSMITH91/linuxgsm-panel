"""Part 6 of the unit suite. Imported for its side effects."""
from unit.part01 import (N, NS, SO, _modfiles, _modpath, _modsrc, _privmod, _sm_core, _sm_cron, _sm_firewall, _sm_hosts, _sub, _ufw_raises_verb, check, eq, skip, glob, json, os, re, sys)  # noqa: F401,E402
from unit import REPO_ROOT as _UNIT_ROOT  # noqa: E402

from unit.part05 import (_ast_scan, _helper, _helper_path, _ilu, _machinery, _priv, _re, _root, _shutil, _sp, _t, _tempfile, _time)  # noqa: F401,E402
check("ufw: _ufw_is_active is false for empty output", _sm_firewall._ufw_is_active("") is False)
check("ufw: _ufw_is_active is not fooled by the word active elsewhere",
      _sm_firewall._ufw_is_active("To    Action\n22    ALLOW  # keep this rule active") is False)

# ── The sshd port change, exercised for real ──────────────────────────────────────────────────
# This is the one privileged sequence whose failure mode is "the operator cannot reach the machine
# any more", so it is tested against a sandboxed filesystem rather than by asserting the argv. The
# property that matters is the ROLLBACK: whatever the host looked like before, a failed change puts
# it back exactly.
_sandbox = _tempfile.mkdtemp(prefix="panel-sshd-")
os.makedirs(os.path.join(_sandbox, "etc/ssh/sshd_config.d"))
os.makedirs(os.path.join(_sandbox, "etc/fail2ban"))


def _sandboxed_helper():
    """The helper module, with every path it writes redirected under a temp dir."""
    _spec = _ilu.spec_from_loader("ph_sandbox",
                                  _machinery.SourceFileLoader("ph_sandbox", _helper_path))
    _m = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_m)
    _m.SSHD_DROPIN = _sandbox + _m.SSHD_DROPIN
    _m.SSHD_DROPIN_BAK = _m.SSHD_DROPIN + ".bak"
    _m.WRITE_TARGETS = dict(_m.WRITE_TARGETS,
                            **{"sshd-port-dropin": (_m.SSHD_DROPIN, 0o644)})
    _m.F2B_JAIL_LOCAL = os.path.join(_sandbox, "etc/fail2ban/jail.local")
    return _m


_h = _sandboxed_helper()

# (a) No drop-in before -> a failed change must leave no drop-in. Getting this wrong leaves an
#     empty file that sshd reads, which is how a "rollback" locks someone out.
_h.do_sshd_backup([], None)
check("sshd: backing up a host with no drop-in creates no snapshot",
      not os.path.exists(_h.SSHD_DROPIN_BAK))
_h.do_write_file(["sshd-port-dropin"], "Port 2222\nPort 22\n")
_h.do_sshd_restore([], None)
check("sshd: rolling back a host that had no drop-in removes the file entirely",
      not os.path.exists(_h.SSHD_DROPIN))

# (b) An existing drop-in must come back byte-identical, comments and all.
_ORIGINAL = "# the operator's own file\nPort 22\nListenAddress 10.0.0.1:22\n"
open(_h.SSHD_DROPIN, "w").write(_ORIGINAL)
_h.do_sshd_backup([], None)
_h.do_write_file(["sshd-port-dropin"], "Port 2222\nPort 22\n")
check("sshd: the new drop-in is what got written",
      open(_h.SSHD_DROPIN).read() == "Port 2222\nPort 22\n")
_h.do_sshd_restore([], None)
check("sshd: rolling back restores the previous drop-in byte for byte",
      open(_h.SSHD_DROPIN).read() == _ORIGINAL)
check("sshd: and the snapshot is consumed, not left lying in sshd_config.d",
      not os.path.exists(_h.SSHD_DROPIN_BAK))

# A rollback that changes permissions is not a rollback. There was a chmod 0o644 on the restore
# path, which both widened the file and threw away whatever mode the operator had set.
import stat as _stat
os.chmod(_h.SSHD_DROPIN, 0o600)
_hardened = open(_h.SSHD_DROPIN).read()
_h.do_sshd_backup([], None)
_h.do_write_file(["sshd-port-dropin"], "Port 2222\n")
_h.do_sshd_restore([], None)
check("sshd: rolling back restores the file's MODE, not just its content",
      _stat.S_IMODE(os.stat(_h.SSHD_DROPIN).st_mode) == 0o600
      and open(_h.SSHD_DROPIN).read() == _hardened,
      oct(_stat.S_IMODE(os.stat(_h.SSHD_DROPIN).st_mode)))

# (c) Discarding the snapshot on success is idempotent — the success path runs it once, but a
#     retry must not turn into an error.
_h.do_sshd_backup([], None)
_h.do_sshd_discard_backup([], None)
_h.do_sshd_discard_backup([], None)
check("sshd: discarding the snapshot twice is not an error",
      not os.path.exists(_h.SSHD_DROPIN_BAK))

# (d) The fail2ban jail edit must touch ONLY the [sshd] section. The sed range it replaces
#     (/^\[sshd\]/,/^\[/) was doing the same job with a regex running as root.
_jail = _h.F2B_JAIL_LOCAL
open(_jail, "w").write("[DEFAULT]\nbantime = 1h\nport = 9999\n\n"
                       "[sshd]\nenabled = true\nport = 22\nmaxretry = 5\n\n"
                       "[nginx]\nport = 80\n")
_h.do_f2b_sshd_ports(["2222,22"], None)
_jail_after = open(_jail).read()
check("f2b: the [sshd] jail gets the new port list",
      "port = 2222,22" in _jail_after.split("[sshd]")[1])
check("f2b: [DEFAULT]'s port is left alone",
      "port = 9999" in _jail_after.split("[sshd]")[0])
check("f2b: another jail's port is left alone", "port = 80" in _jail_after)
os.chmod(_jail, 0o640)
_h.do_f2b_sshd_ports(["22"], None)
check("f2b: editing jail.local keeps the mode it already had",
      _stat.S_IMODE(os.stat(_jail).st_mode) == 0o640,
      oct(_stat.S_IMODE(os.stat(_jail).st_mode)))
check("f2b: a host with no jail.local is a no-op, not a failure",
      _h.do_f2b_sshd_ports(["22"], None) == 0)

# (e) The deferred reboot must RETURN IMMEDIATELY and fire later — that is the whole reason it was
#     a backgrounded subshell. Run in a subprocess against a fake reboot binary, so this can be
#     asserted without the suite rebooting the machine it is running on.
_fake_reboot = os.path.join(_sandbox, "fake-reboot")
_marker = os.path.join(_sandbox, "fired")
open(_fake_reboot, "w").write("#!/bin/sh\necho fired > %s\n" % _marker)
os.chmod(_fake_reboot, 0o755)
_probe = (
    "import importlib.util as u, importlib.machinery as m, time, sys;"
    "s=u.spec_from_loader('p', m.SourceFileLoader('p', %r));"
    "mod=u.module_from_spec(s); s.loader.exec_module(mod);"
    "mod.resolve=lambda p: %r; mod.REBOOT_DELAY_SECONDS=1;"
    "t=time.time(); mod.do_reboot_delayed([], None);"
    "print('ELAPSED=%%.2f' %% (time.time()-t))" % (_helper_path, _fake_reboot)
)
try:
    _r = _sp.run([sys.executable, "-c", _probe], capture_output=True, text=True, timeout=60)
    _parts = _r.stdout.strip().rsplit("ELAPSED=", 1)
    _elapsed = float(_parts[1]) if len(_parts) == 2 else 9.0   # no marker -> treat as a failure
    check("reboot: the call returns at once instead of blocking for the delay",
          _elapsed < 0.5, _r.stdout.strip() + _r.stderr.strip()[:80])
    check("reboot: nothing has fired yet when it returns", not os.path.exists(_marker))
    _t_end = _time.time() + 8
    while not os.path.exists(_marker) and _time.time() < _t_end:
        _time.sleep(0.2)
    check("reboot: the detached child fires after the delay", os.path.exists(_marker))
except Exception as _e:                     # a sandbox that forbids fork should not fail the suite
    skip("reboot: the detached child fires after the delay", _e)

_shutil.rmtree(_sandbox, ignore_errors=True)


# ── The three transports, including the one every existing install is actually on ──────────────
# run_privileged() has three paths and until now the suite exercised none of them. That matters
# most for the middle one: a host only gains the helper when install.sh is next run as ROOT, and
# the panel cannot place a root-owned file outside its own checkout — so every already-deployed
# install is running the fallback right now. If it were wrong, the firewall, fail2ban, apt and user
# management would all be broken on exactly the hosts that upgraded.
_T_LOCAL = NS(is_local=True, auth_method="local", sudo_enabled=True, linuxgsm_user="")
_T_REMOTE = NS(is_local=False, auth_method="key", sudo_enabled=True, linuxgsm_user="", host="h")
_T_SAMPLE = [
    ("ufw-allow-port", ["27015", "codserver"], "ufw allow 27015 comment codserver 2>&1"),
    ("f2b-unban", ["sshd", "203.0.113.5"], "fail2ban-client set sshd unbanip 203.0.113.5 2>&1"),
    ("service-restart", ["fail2ban"], "systemctl restart fail2ban 2>&1"),
    ("apt-install", ["curl"], "DEBIAN_FRONTEND=noninteractive apt-get install -y curl 2>&1"),
    ("journal", ["ssh", "400"], "journalctl -u ssh -u sshd --no-pager -n 400 2>&1"),
    ("user-remove-home", ["codserver"], "rm -rf -- /home/codserver 2>&1"),
]

_orig_rl, _orig_rc2, _orig_argv = _sm_core._run_local, _sm_core.run_command, _sm_core._exec_local_argv
_orig_helper_state = dict(_sm_core._HELPER_STATE)
try:
    # (a) local, helper NOT installed -> the pre-helper shell string, unchanged.
    _seen = []
    _sm_core._run_local = lambda cmd, timeout=30, sudo=False: (_seen.append((cmd, sudo)), ("", "", 0))[1]
    _sm_core._HELPER_STATE["present"] = False
    for _v, _a, _want in _T_SAMPLE:
        _sm_core.run_privileged(_T_LOCAL, _v, _a, timeout=5)
    check("transport: with no helper installed, the local path runs the pre-helper command",
          [c for c, _s in _seen] == [w for _v, _a, w in _T_SAMPLE],
          str([c for c, _s in _seen][:2]))
    check("transport: and it still escalates (sudo=True), or nothing privileged would work",
          all(_s is True for _c, _s in _seen))

    # (b) local, helper installed -> argv through the helper, and no shell anywhere.
    _argvs = []
    _sm_core._exec_local_argv = lambda argv, timeout=30, stdin_text=None: (
        _argvs.append(argv), ("", "", 0))[1]
    _sm_core._HELPER_STATE["present"] = True
    for _v, _a, _w in _T_SAMPLE:
        _sm_core.run_privileged(_T_LOCAL, _v, _a, timeout=5)
    check("transport: with the helper installed, the local path invokes it with argv",
          all(a[:3] == ["sudo", "-n", _priv.HELPER_PATH] for a in _argvs), str(_argvs[:1]))
    check("transport: the helper path never builds a shell command",
          not any("bash" in x or "2>&1" in x for a in _argvs for x in a), str(_argvs[:1]))
    check("transport: the verb and its arguments arrive as separate argv elements",
          _argvs[0][3:] == ["ufw-allow-port", "27015", "codserver"], str(_argvs[0]))

    # (c) remote -> the shell string over SSH, whatever the local helper situation is.
    _rem = []
    _sm_core.run_command = lambda s_, c, **k: (_rem.append((c, k.get("sudo"))), ("", "", 0))[1]
    for _v, _a, _w in _T_SAMPLE:
        _sm_core.run_privileged(_T_REMOTE, _v, _a, timeout=5)
    check("transport: a remote host gets the same command it always got",
          [c for c, _s in _rem] == [w for _v, _a, w in _T_SAMPLE], str([c for c, _s in _rem][:2]))
    check("transport: the local helper being present does not change what a remote receives",
          all(_s is True for _c, _s in _rem))
finally:
    _sm_core._run_local, _sm_core.run_command, _sm_core._exec_local_argv = _orig_rl, _orig_rc2, _orig_argv
    _sm_core._HELPER_STATE.clear()
    _sm_core._HELPER_STATE.update(_orig_helper_state)


# ── the REMOTE fail2ban top-IPs report ────────────────────────────────────────────────────────
# The remote twin of system_ops.fail2ban_top_ips. #118 converted the local one; this copy still
# carried the five-stage root pipeline, which is how two copies of one behaviour drift. It shares
# the tally now — and a mutation that skipped the tally entirely left the suite green until this
# test existed, because nothing exercised the remote path end to end.
_orig_rt_rp, _orig_rt_ov = _sm_core.run_privileged, _sm_hosts.remote_fail2ban_overview
try:
    _RAW = "\n".join([
        "2026-09-03 10:00:00 x [sshd] Found 203.0.113.5",
        "2026-09-03 10:00:01 x [sshd] Found 203.0.113.5",
        "2026-09-03 10:00:02 x [sshd] Ban 203.0.113.5",
        "2026-09-03 10:00:03 x [sshd] Found 198.51.100.9",
    ])
    _rt_args = []
    _sm_core.run_privileged = lambda s_, v, a=(), **k: (_rt_args.append((v, list(a))), (_RAW, "", 0))[1]
    _sm_hosts.remote_fail2ban_overview = lambda s_: {"jails": [{"banned_ips": ["203.0.113.5"]}]}
    _rt = _sm_hosts.remote_fail2ban_top_ips(object(), limit=20, days=7)
    _rt_by = {r["ip"]: r for r in _rt}
    check("remote top-IPs: the raw log lines are tallied, not passed through",
          "203.0.113.5" in _rt_by and _rt_by["203.0.113.5"]["attempts"] == 2
          and _rt_by["203.0.113.5"]["bans"] == 1, str(_rt))
    check("remote top-IPs: a second IP is counted separately",
          _rt_by.get("198.51.100.9", {}).get("attempts") == 1, str(_rt))
    check("remote top-IPs: currently-banned IPs are marked from the jail overview",
          _rt_by["203.0.113.5"]["banned_now"] is True
          and _rt_by["198.51.100.9"]["banned_now"] is False, str(_rt))
    check("remote top-IPs: the verb is asked for the log lines, with a bare date as its cutoff",
          _rt_args and _rt_args[0][0] == "f2b-log-lines"
          and _re.fullmatch(r"\d{4}-\d{2}-\d{2}", _rt_args[0][1][0]) is not None,
          str(_rt_args[:1]))
    check("remote top-IPs: that cutoff is one privileged.py would accept",
          _priv.check_args("f2b-log-lines", _rt_args[0][1]) == _rt_args[0][1], str(_rt_args[:1]))
finally:
    _sm_core.run_privileged, _sm_hosts.remote_fail2ban_overview = _orig_rt_rp, _orig_rt_ov


# ── the content scan ──────────────────────────────────────────────────────────────────────────
# Was a shell loop over /home that built its inner list by interpolating the game keys, running as
# root. Read-only, but still a composed root command. Exercised against a sandboxed /home holding
# a user with two of the wanted games, one with none of them, one with no serverfiles at all, and
# one whose NAME is not something the panel would ever pass to a verb.
try:
    _scanroot = _tempfile.mkdtemp(prefix="panel-scan-")
    for _d in ("srcds/serverfiles/cstrike", "srcds/serverfiles/hl2",
               "gmodserver/serverfiles/tf2", "nothing", "bad;name/serverfiles/cstrike"):
        os.makedirs(os.path.join(_scanroot, _d), exist_ok=True)
    _spec_s = _ilu.spec_from_loader("ph_scan", _machinery.SourceFileLoader("ph_scan", _helper_path))
    _hs = _ilu.module_from_spec(_spec_s)
    _spec_s.loader.exec_module(_hs)
    _hs.HOME_ROOT = _scanroot
    _hs.home_of = lambda u, _r=_scanroot: _r + "/" + _hs.v_username(u)
    import io as _io_s
    _sbuf = _io_s.StringIO()
    _ssave = sys.stdout
    sys.stdout = _sbuf
    try:
        _hs.do_content_scan(["cstrike", "hl2"], None)
    finally:
        sys.stdout = _ssave
    _hits = sorted(ln for ln in _sbuf.getvalue().splitlines() if ln)
    eq("content scan: reports every wanted game a user actually has",
       _hits, ["HIT|srcds|cstrike", "HIT|srcds|hl2"])
    check("content scan: a user with serverfiles but none of the wanted games is not reported",
          not any("gmodserver" in h for h in _hits), str(_hits))
    check("content scan: a user with no serverfiles at all is not reported",
          not any("nothing" in h for h in _hits), str(_hits))
    check("content scan: a /home entry whose NAME the panel would never use is skipped",
          not any("bad" in h for h in _hits), str(_hits))
    _shutil.rmtree(_scanroot, ignore_errors=True)
except OSError as _e:
    skip("content scan", _e)


# ── the detached OS-update runner ─────────────────────────────────────────────────────────────
# Was `setsid bash -c '<seven statements>' </dev/null >/dev/null 2>&1 &`. Exercised for real
# against a sandboxed log and a FAKE apt-get, so the suite cannot upgrade the machine it runs on.
#
# Run in a SUBPROCESS, and that is not tidiness. do_os_update_run ends its grandchild with
# os._exit(): if the fork ever goes missing, that _exit runs in the CALLER's process — which, in
# process, means this suite terminates mid-run with status 0. No failures printed, no summary, a
# green exit code. A mutation that removed the fork did exactly that and "passed". Out of process,
# the same mutation shows up as missing output and a wrong elapsed time.
_ho_done_marker = _helper.OS_UPDATE_DONE
_osu = None
try:
    _osu = _tempfile.mkdtemp(prefix="panel-osupd-")
except OSError as _e:
    skip("os update: detached runner", _e)
if _osu:
    _fake_apt = os.path.join(_osu, "fake-apt")
    open(_fake_apt, "w").write("#!/bin/sh\necho \"fake apt: $*\"\n"
                               "case \"$*\" in *full-upgrade*) exit 7 ;; esac\nexit 0\n")
    os.chmod(_fake_apt, 0o755)
    _oslog = os.path.join(_osu, "os-update.log")
    _osprobe = (
        "import importlib.util as u, importlib.machinery as m, time, sys;"
        "s=u.spec_from_loader('p', m.SourceFileLoader('p', %r));"
        "mod=u.module_from_spec(s); s.loader.exec_module(mod);"
        "mod.OS_UPDATE_LOG=%r; mod.resolve=lambda p, f=%r: f;"
        "t=time.time(); mod.do_os_update_run([], None);"
        "sys.stderr.write('ELAPSED=%%.2f' %% (time.time()-t))"
        % (_helper_path, _oslog, _fake_apt)
    )
    _osr = _sp.run([sys.executable, "-c", _osprobe], capture_output=True, text=True, timeout=90)
    _osparts = _osr.stderr.rsplit("ELAPSED=", 1)
    _oselapsed = float(_osparts[1]) if len(_osparts) == 2 else 99.0
    check("os update: the call returns at once — the UI polls the log, it does not wait",
          _oselapsed < 1.0, "%.2f (stderr=%r)" % (_oselapsed, _osr.stderr[-60:]))
    check("os update: it reports that the job launched, and RETURNS to its caller",
          _priv.OS_UPDATE_STARTED in _osr.stdout and len(_osparts) == 2,
          "stdout=%r stderr=%r" % (_osr.stdout[-40:], _osr.stderr[-40:]))
    _osdeadline = _time.time() + 15
    _olog = ""
    while _time.time() < _osdeadline:
        try:
            _olog = open(_oslog).read()
            if _ho_done_marker in _olog:
                break
        except OSError:
            pass
        _time.sleep(0.2)
    check("os update: the log opens with a dated header", _olog.startswith("=== OS update started"),
          _olog[:60])
    check("os update: apt update, full-upgrade and autoremove all ran",
          "fake apt: update" in _olog and "full-upgrade" in _olog and "autoremove" in _olog, _olog)
    check("os update: phased updates are included, so a re-check actually reaches zero",
          "Always-Include-Phased-Updates=true" in _olog, _olog)
    check("os update: a config file the operator edited is kept",
          "--force-confold" in _olog and "--force-confdef" in _olog, _olog)
    check("os update: the sentinel carries the REAL exit code, not a fixed one",
          (_ho_done_marker + "7") in _olog, _olog[-80:])
    check("os update: the writer and the reader agree on the sentinel",
          _helper.OS_UPDATE_DONE == _priv.OS_UPDATE_DONE == _sm_hosts._OS_UPDATE_DONE)

    # A job that dies before writing its own sentinel must still write one. Without it the UI's
    # popup polls forever, which looks exactly like "the update is taking a long time". Provoked
    # by making apt unresolvable, so the run fails at its first step.
    _osfail = os.path.join(_osu, "failed.log")
    _osfprobe = (
        "import importlib.util as u, importlib.machinery as m;"
        "s=u.spec_from_loader('p', m.SourceFileLoader('p', %r));"
        "mod=u.module_from_spec(s); s.loader.exec_module(mod);"
        "mod.OS_UPDATE_LOG=%r;"
        "mod.resolve=lambda p: (_ for _ in ()).throw(FileNotFoundError('apt-get'));"
        "mod.do_os_update_run([], None)" % (_helper_path, _osfail)
    )
    _osfr = _sp.run([sys.executable, "-c", _osfprobe], capture_output=True, text=True, timeout=60)
    check("os update: a job that cannot start still reports STARTED to its caller",
          _priv.OS_UPDATE_STARTED in _osfr.stdout, repr(_osfr.stdout))
    _osfdeadline = _time.time() + 10
    _osftxt = ""
    while _time.time() < _osfdeadline:
        try:
            _osftxt = open(_osfail).read()
            if _ho_done_marker in _osftxt:
                break
        except OSError:
            pass
        _time.sleep(0.2)
    check("os update: and it writes a FAILURE sentinel, so the popup stops waiting",
          (_ho_done_marker + "-1") in _osftxt, repr(_osftxt))
    _shutil.rmtree(_osu, ignore_errors=True)


# ── cron run times, read from cron's own journal ──────────────────────────────────────────────
# Was `journalctl _COMM=cron … | grep -F '(<user>) CMD ' | tail -n 800` — the user name went into a
# grep pattern running as root. The verb reads the window; the filtering is Python. The per-user
# filter is the part that matters: without it one game user's cron history is attributed to
# another, and a mutation that dropped it left the suite green until this test existed.
_CRON_JOURNAL = "\n".join([
    "1788000000 host CRON[1]: (codserver) CMD (/home/codserver/codserver monitor)",
    "1788000060 host CRON[2]: (gmodserver) CMD (/home/gmodserver/gmodserver update)",
    "1788000120 host CRON[3]: (codserver) CMD (/home/codserver/codserver update-lgsm)",
    "1788000180 host CRON[4]: (codserver) CMD (/home/codserver/codserver monitor)",
    "not-an-epoch host CRON[5]: (codserver) CMD (/home/codserver/codserver bogus)",
])
_orig_cron_rp = _sm_core.run_privileged
try:
    _sm_core.run_privileged = lambda s_, v, a=(), **k: (_CRON_JOURNAL, "", 0)
    _times = _sm_cron._read_cron_run_times(object(), "codserver")
    check("cron times: only THIS user's lines are counted",
          "/home/gmodserver/gmodserver update" not in _times, str(sorted(_times)))
    check("cron times: this user's commands are all present",
          "/home/codserver/codserver monitor" in _times
          and "/home/codserver/codserver update-lgsm" in _times, str(sorted(_times)))
    check("cron times: a repeated command keeps the LATEST run",
          _times.get("/home/codserver/codserver monitor") == 1788000180,
          str(_times.get("/home/codserver/codserver monitor")))
    check("cron times: a line whose first field is not an epoch is skipped",
          "/home/codserver/codserver bogus" not in _times, str(sorted(_times)))
    _sm_core.run_privileged = lambda s_, v, a=(), **k: ("", "", 0)
    eq("cron times: no journal output is no times",
       _sm_cron._read_cron_run_times(object(), "codserver"), {})
finally:
    _sm_core.run_privileged = _orig_cron_rp


# ── sshd hardening, and the swap file's precedence bug ────────────────────────────────────────
# The hardening was four `sed -i 's/^#\?Key.*/Key value/'` substitutions joined with ';' in one
# root shell. Exercised here against a real sshd_config: a commented directive, an already-set one,
# and one that is absent entirely.
try:
    _hdir = _tempfile.mkdtemp(prefix="panel-sshd-cfg-")
    _spec_h2 = _ilu.spec_from_loader("ph_hard", _machinery.SourceFileLoader("ph_hard", _helper_path))
    _hh = _ilu.module_from_spec(_spec_h2)
    _spec_h2.loader.exec_module(_hh)
    _hh.SSHD_CONFIG = os.path.join(_hdir, "sshd_config")
    open(_hh.SSHD_CONFIG, "w").write(
        "# a comment\n#ClientAliveInterval 120\nClientAliveCountMax 9\nPort 22\n")
    os.chmod(_hh.SSHD_CONFIG, 0o600)
    _hh.do_sshd_set_directive(["ClientAliveInterval", "300"], None)
    _hh.do_sshd_set_directive(["ClientAliveCountMax", "2"], None)
    _hh.do_sshd_set_directive(["PermitRootLogin", "prohibit-password"], None)
    _cfg = open(_hh.SSHD_CONFIG).read()
    check("sshd hardening: a COMMENTED directive is replaced, not duplicated",
          "ClientAliveInterval 300" in _cfg and "#ClientAliveInterval" not in _cfg, _cfg)
    check("sshd hardening: an already-set directive is replaced in place",
          "ClientAliveCountMax 2" in _cfg and "ClientAliveCountMax 9" not in _cfg, _cfg)
    check("sshd hardening: a directive that was ABSENT is appended",
          "PermitRootLogin prohibit-password" in _cfg, _cfg)
    check("sshd hardening: unrelated lines are left alone", "Port 22" in _cfg, _cfg)
    check("sshd hardening: the file keeps the mode it had",
          _stat.S_IMODE(os.stat(_hh.SSHD_CONFIG).st_mode) == 0o600)
    _shutil.rmtree(_hdir, ignore_errors=True)
except OSError as _e:
    skip("sshd hardening", _e)

# The swap shell form had a precedence bug. `a && b && c && grep -q … || echo … >> /etc/fstab`
# parses as `((a && b) && c && grep) || echo`, so the fstab line was appended whenever ANY step
# failed — a host that ran out of space in fallocate still got a swap entry pointing at a file that
# was never formatted. The Python version appends only when the swap is really on and the line is
# absent, so that is what is asserted.
check("swap: the shell form's `a && b || c` appends on ANY failure, not just the grep",
      _sp.run(["bash", "-c", "false && true && grep -q x /dev/null || echo APPENDED"],
              capture_output=True, text=True).stdout.strip() == "APPENDED")
check("swap: the braced form the remote rendering uses does not",
      _sp.run(["bash", "-c", "false && true && { grep -q x /dev/null || echo APPENDED; }"],
              capture_output=True, text=True).stdout.strip() == "")
check("swap: the remote rendering is the braced form",
      "{ grep -q" in _priv.remote_command("create-swapfile", []),
      _priv.remote_command("create-swapfile", []))


# ── the fail2ban top-IPs pipeline ─────────────────────────────────────────────────────────────
# Was five stages — zcat | awk (date filter) | grep | awk (tally) | sort | head — running as root,
# with the cutoff date and the row limit interpolated into it. The verb now does the READ half only
# (fixed glob, gzip handled in Python) and the tally is _tally_f2b_lines. These assert the Python
# reproduces what the awk produced, because "it looks equivalent" is how a rewrite loses a case.
from panel.ops import system_ops as _so_f2b
_F2B_LINES = "\n".join([
    "2026-09-03 10:00:00 x [sshd] Found 203.0.113.5",
    "2026-09-03 10:00:01 x [sshd] Found 203.0.113.5",
    "2026-09-03 10:00:02 x [sshd] Ban 203.0.113.5",
    "2026-09-03 10:00:03 x [linuxgsm-panel] Found 203.0.113.5",
    "2026-09-03 10:00:04 x [sshd] Found 198.51.100.9",
    "2026-09-03 10:00:05 x [sshd] Ban 2001:db8::1",
    "2026-09-03 10:00:06 x [sshd] Unban 203.0.113.5",
])
_tallied = _so_f2b._tally_f2b_lines(_F2B_LINES, 20)
_trows = _so_f2b._parse_top_ips(_tallied, set(), {})
_by_ip = {r["ip"]: r for r in _trows}
check("f2b top-IPs: Found and Ban are counted separately, per IP",
      _by_ip["203.0.113.5"]["attempts"] == 3 and _by_ip["203.0.113.5"]["bans"] == 1, _tallied)
check("f2b top-IPs: an IP seen in two jails lists both, once each",
      _by_ip["203.0.113.5"]["jails"] == ["sshd", "linuxgsm-panel"], str(_by_ip["203.0.113.5"]))
check("f2b top-IPs: an Unban line is not an event", "Unban" not in _tallied)
check("f2b top-IPs: an IPv6 address survives the parse", "2001:db8::1" in _by_ip)
check("f2b top-IPs: ranked by attempts, most first",
      [r["ip"] for r in _trows][0] == "203.0.113.5", str([r["ip"] for r in _trows]))
check("f2b top-IPs: the limit is honoured",
      len(_so_f2b._tally_f2b_lines(_F2B_LINES, 1).splitlines()) == 1)
eq("f2b top-IPs: no input is no rows", _so_f2b._tally_f2b_lines("", 20), "")
eq("f2b top-IPs: lines that are not events are no rows",
   _so_f2b._tally_f2b_lines("nothing to see here\n", 20), "")

# The read half, over a real plain log AND a real gzipped rotation.
try:
    _logdir = _tempfile.mkdtemp(prefix="panel-f2b-")
    open(os.path.join(_logdir, "fail2ban.log"), "w").write(
        "2026-09-03 10:00:00 x [sshd] Found 203.0.113.5\n"
        "2026-09-01 09:00:00 x [sshd] Found 198.51.100.9\n")     # before the cutoff
    import gzip as _gzip_t
    with _gzip_t.open(os.path.join(_logdir, "fail2ban.log.2.gz"), "wt") as _gf:
        _gf.write("2026-09-04 11:00:00 x [sshd] Ban 203.0.113.5\n"
                  "2026-09-03 08:00:00 x [sshd] Unban 203.0.113.5\n")
    _spec_l = _ilu.spec_from_loader("ph_logs", _machinery.SourceFileLoader("ph_logs", _helper_path))
    _hl = _ilu.module_from_spec(_spec_l)
    _spec_l.loader.exec_module(_hl)
    _hl.F2B_LOG_GLOB = os.path.join(_logdir, "fail2ban.log*")
    import io as _io_t
    _buf = _io_t.StringIO()
    _stdout_save = sys.stdout
    sys.stdout = _buf
    try:
        _hl.do_f2b_log_lines(["2026-09-02"], None)
    finally:
        sys.stdout = _stdout_save
    _got = [ln for ln in _buf.getvalue().splitlines() if ln]
    check("f2b log read: the plain log is read", any("Found 203.0.113.5" in ln for ln in _got), str(_got))
    check("f2b log read: a GZIPPED rotation is read too — zcat's job, done in Python",
          any("Ban 203.0.113.5" in ln for ln in _got), str(_got))
    check("f2b log read: a line before the cutoff is dropped",
          not any("198.51.100.9" in ln for ln in _got), str(_got))
    check("f2b log read: a line that is not a Ban/Found is dropped",
          not any("Unban" in ln for ln in _got), str(_got))
    _shutil.rmtree(_logdir, ignore_errors=True)
except OSError as _e:
    skip("f2b log read", _e)


# ── isdigit() is not "int() will accept this" ─────────────────────────────────────────────────
# Fuzzing found this, in _parse_top_ips: `int(parts[0]) if parts[0].isdigit() else 0` raised
# ValueError on "¹". str.isdigit() is True for Unicode No characters — superscripts — while int()
# only accepts Nd. So the guard passed and the conversion blew up, one line later.
#
# It was never one site. The same `.isdigit()` immediately before `int()` appeared 35 times across
# app, auth, manage, system_ops and ssh_manager, including two reachable from data the panel reads
# off a game server (a queryport from its config, a player count from command output) and two in
# the Flask-Login user loader. isdecimal() is exactly the predicate that was wanted: True iff every
# character is Nd, which is precisely what int() accepts.
check("unicode: isdigit() accepts a superscript, isdecimal() does not — that gap IS the bug",
      "\u00b9".isdigit() and not "\u00b9".isdecimal())
_int_raised = False
try:
    int("\u00b9")
except ValueError:
    _int_raised = True
check("unicode: int() rejects it, so isdecimal() is the guard that matches int()", _int_raised)
check("unicode: isdecimal() still accepts a non-ASCII DECIMAL digit, so nothing legitimate is lost",
      "٥".isdecimal() and int("٥") == 5)

# No module may guard an int() with isdigit() again.
_isdigit_users = []
for _f in ("app.py", "auth.py", "manage.py", "models.py", "system_ops.py", "ssh_manager.py",
           "notifications.py", "backup.py", "db_maintenance.py", "tailscale_integration.py",
           "config.py", "i18n.py", "privileged.py", "clock.py"):
    # _modpath, not a root join with an exists() skip: when these modules moved under panel/
    # the old form silently matched nothing and still reported green.
    for _fp2 in _modfiles(_f):
     for _i, _line in enumerate(open(_fp2, encoding="utf-8"), 1):
        if ".isdigit()" in _line.split("#", 1)[0]:
            _isdigit_users.append("%s:%d" % (_f, _i))
check("unicode: no module uses .isdigit() — isdecimal() is the one that matches int()",
      not _isdigit_users, ", ".join(_isdigit_users[:4]))

# The crashing input itself, replayed.
from panel.ops import system_ops as _so_top
_CRASH = "¹\t²\t203.0.113.5\tsshd\n5\t2\t198.51.100.9\tsshd,panel\n"
try:
    _rows = _so_top._parse_top_ips(_CRASH, set(), {})
    check("fail2ban top-IPs: the fuzz crash input parses instead of raising",
          len(_rows) == 2 and _rows[0]["attempts"] == 0 and _rows[1]["attempts"] == 5,
          str(_rows))
except Exception as _e:
    check("fail2ban top-IPs: the fuzz crash input parses instead of raising", False, repr(_e))


# ── The escalation census: a ratchet, and a correction ────────────────────────────────────────
# I reported the conversion's progress for four PRs as "113 sites -> N" while counting only ONE of
# the two ways the panel escalates on its own host. run_command(..., sudo=True) is the obvious one.
# _sudo_sh() is the other: it builds `sudo bash -c '<pipeline>'` itself and then passes sudo=False,
# so it is invisible to a search for sudo=True — and there were 18 of them the whole time.
#
# This counts both, and ratchets: the ceilings below may be lowered as call sites convert, never
# raised. A new escalation written as a shell string fails this test instead of going unnoticed.
import ast as _ast

_ESCALATION_FILES = ["app.py", "auth.py", "ssh_manager.py", "system_ops.py", "notifications.py",
                     "backup.py", "db_maintenance.py", "tailscale_integration.py", "manage.py"]
_CEILING = {"sudo=True": 4, "_sudo_sh": 0}   # measured at the time of writing; lower only

def _is_dispatch(call):
    """True when this escalation is NOT a call site composing a shell string.

    Two shapes qualify. run_privileged() itself takes a `sudo` keyword — passing it explicitly is
    still a VERB call, not a shell string, and counting those overstated the work by one until it
    was noticed. And run_privileged / write_root_file / _run_verb each end in a
    run_command/_run_local/_run with sudo=True, passing a command built by privileged.py.

    run_privileged(), write_root_file() and _run_verb() each end in a run_command/_run_local/_run
    with sudo=True, passing a command built by privileged.py. Counting those as "call sites still
    composing a shell string" overstates the work left by four — the number below is quoted in
    SECURITY.md, so it should mean what it says."""
    if getattr(call.func, "attr", getattr(call.func, "id", "")) in ("run_privileged", "_run_verb"):
        return True                       # a verb call, however it spells its sudo argument
    for _arg in list(call.args) + [k.value for k in call.keywords]:
        for _sub in _ast.walk(_arg):
            if (isinstance(_sub, _ast.Call)
                    and isinstance(_sub.func, _ast.Attribute)
                    and getattr(_sub.func.value, "id", "") == "_priv"
                    and _sub.func.attr in ("remote_command", "remote_write_command",
                                           "remote_content_cron_command")):
                return True
    return False


_census = {"sudo=True": 0, "_sudo_sh": 0}
for _f in _ESCALATION_FILES:
    _tree = _ast.parse("\n".join(open(_p, encoding="utf-8").read() for _p in _modfiles(_f)))
    for _n in _ast.walk(_tree):
        if not isinstance(_n, _ast.Call):
            continue
        if getattr(_n.func, "attr", getattr(_n.func, "id", "")) == "_sudo_sh":
            _census["_sudo_sh"] += 1
        for _k in _n.keywords:
            if (_k.arg == "sudo" and isinstance(_k.value, _ast.Constant)
                    and _k.value.value is True and not _is_dispatch(_n)):
                _census["sudo=True"] += 1

# The exclusion above could go over-broad and quietly shrink the number the ratchet guards — a
# _is_dispatch() that returned True for everything would report zero remaining work and still pass.
# So count what it excludes and pin that: there are exactly four transports (run_privileged and
# write_root_file in ssh_manager, twice each for the helper-present and no-helper paths, plus
# _run_verb in system_ops), plus two for write_content_cron, whose destination is per-user and so
# cannot live in WRITE_TARGETS. Raise this only when the verb layer genuinely gains another one.
_excluded = 0
for _f in _ESCALATION_FILES:
    _tree = _ast.parse("\n".join(open(_p, encoding="utf-8").read() for _p in _modfiles(_f)))
    for _n in _ast.walk(_tree):
        if not isinstance(_n, _ast.Call):
            continue
        for _k in _n.keywords:
            if (_k.arg == "sudo" and isinstance(_k.value, _ast.Constant)
                    and _k.value.value is True and _is_dispatch(_n)):
                _excluded += 1
check("escalation census: the exclusion covers exactly the 6 known transports",
      _excluded == 6, "excluded %d" % _excluded)

for _kind, _limit in _CEILING.items():
    check("escalation census: %s sites <= %d (currently %d) — ratchet, never raise"
          % (_kind, _limit, _census[_kind]),
          _census[_kind] <= _limit, "found %d" % _census[_kind])

# tailscale-serve is the only verb whose upstream URL is ASSEMBLED on the far side rather than
# handed in. These prove a caller cannot aim Tailscale Serve at anything but loopback on this box —
# which is a guarantee the old `sudo tailscale <args>` form could not make at all.
check("privileged: tailscale-serve builds a loopback upstream, modern grammar",
      _priv.tool_argv("tailscale-serve", ["serve", "modern", "/", "http", "5000"])
      == ["tailscale", "serve", "--bg", "--https=443", "http://127.0.0.1:5000"])
check("privileged: tailscale-serve builds a loopback upstream, legacy grammar",
      _priv.tool_argv("tailscale-serve", ["funnel", "legacy", "/panel", "https+insecure", "8443"])
      == ["tailscale", "funnel", "--bg", "--https", "443", "/panel",
          "https+insecure://127.0.0.1:8443"])

# ── ts_serve_argv validates its OWN arguments, not just the verb table's ───────────────────────
# Everything above goes through tool_argv, which runs the verb table's validators first. But
# tailscale_integration._ts_serve_args() calls ts_serve_argv() DIRECTLY to build the unprivileged
# command — and that path is tried FIRST, with the root verb only as a fallback. So the verb table
# was guarding the branch that was least likely to run.
#
# `mount` comes straight from the JSON body of POST /api/tailscale/serve. In the legacy grammar it
# is a BARE POSITIONAL, so before this was fixed, "--exit-node=evil" went into the tailscale argv
# as an OPTION rather than a path — argv form stops shell injection, not argument injection. CodeQL
# py/command-line-injection #375 traced exactly that, request body to subprocess, and was right; an
# older dismissal of the same alert had called it a false positive on the grounds that there is no
# shell, which is true and does not address this.
#
# These call the function DIRECTLY, the way the unprivileged path does. Going through tool_argv
# here would test the wrong door.
for _m in ("--exit-node=evil", "-T", "--set-path=/x", "../../etc", "//evil.example.com",
           "/a b", "/x\ty", "-"):
    _raised = False
    try:
        _priv.ts_serve_argv("serve", "legacy", _m, "http", "5000")
    except _priv.VerbError:
        _raised = True
    check("privileged: ts_serve_argv itself rejects mount %r (direct call, no verb table)" % _m,
          _raised)
# ── _ts_mount REBUILDS its result from a literal alphabet ─────────────────────────────────────
# Two properties, and the first is the one that matters if the regex is ever edited wrong: the
# returned string can only contain characters from _MOUNT_ALPHABET, whatever the pattern says.
# The second is why CodeQL alert #375 stayed open after the validation was added — a function that
# validates and hands back the caller's own object reads as pass-through to a taint tracker, so the
# flow ran straight through it. Rebuilding means the result carries no data from the request.
for _ok in ("/", "/panel", "/a/b/c", "/x.y_z-1", "/" + "a" * 32):
    eq("privileged: _ts_mount(%r) is unchanged in value" % _ok, _priv._ts_mount(_ok), _ok)
    check("privileged: _ts_mount(%r) returns characters from the literal alphabet only" % _ok,
          all(c in _priv._MOUNT_ALPHABET for c in _priv._ts_mount(_ok)))
check("privileged: _ts_mount does not hand back the caller's own object",
      _priv._ts_mount("".join(["/", "panel"])) is not None)
_mnt_in = "".join(["/", "p", "a", "n", "e", "l"])          # built at runtime, not interned
check("privileged: _ts_mount's result is a NEW string, not the input object",
      _priv._ts_mount(_mnt_in) is not _mnt_in)
check("privileged: the alphabet itself contains nothing shell- or option-significant",
      not any(c in _priv._MOUNT_ALPHABET for c in " \t\n;|&$`'\"\\()<>*?[]{}~!#%^+=,:@"))

check("privileged: ts_serve_argv still builds the legitimate modern argv",
      _priv.ts_serve_argv("serve", "modern", "/panel", "http", "5000")
      == ["tailscale", "serve", "--bg", "--https=443", "--set-path=/panel",
          "http://127.0.0.1:5000"])
check("privileged: ts_serve_argv still builds the legitimate legacy argv",
      _priv.ts_serve_argv("funnel", "legacy", "/", "https+insecure", "8443")
      == ["tailscale", "funnel", "--bg", "--https", "443", "/",
          "https+insecure://127.0.0.1:8443"])
for _bad_verb, _bad_gram, _bad_scheme, _bad_port in (
        ("logout", "legacy", "http", "5000"), ("serve", "sneaky", "http", "5000"),
        ("serve", "legacy", "ftp", "5000"), ("serve", "legacy", "http", "99999")):
    _raised = False
    try:
        _priv.ts_serve_argv(_bad_verb, _bad_gram, "/", _bad_scheme, _bad_port)
    except _priv.VerbError:
        _raised = True
    check("privileged: ts_serve_argv rejects (%s,%s,%s,%s) on a direct call"
          % (_bad_verb, _bad_gram, _bad_scheme, _bad_port), _raised)
for _bad in (["serve", "modern", "../../etc", "http", "5000"],
             ["serve", "modern", "//evil.example.com", "http", "5000"],
             ["serve", "modern", "/", "ftp", "5000"],
             ["logout", "modern", "/", "http", "5000"],
             ["serve", "modern", "/", "http", "0"],
             ["serve", "sneaky", "/", "http", "5000"]):
    check("privileged: tailscale-serve refuses %r" % (_bad,),
          _ufw_raises_verb(lambda b=_bad: _priv.check_args("tailscale-serve", b)))
# ── The offline DB repair: the path comes from root's config, never from the caller ────────────
# do_panel_db_repair takes ZERO arguments. That is the security property, not a convenience: the
# old form composed `sudo systemd-run ... bash -c "<panel venv python> <panel dir>/db_maintenance.py"`,
# so root ran the panel user's interpreter on the panel user's script out of a checkout that
# `git pull` rewrites. A verb that accepted a path would be the same hole with validation bolted on.
_dbr_conf = _helper.PANEL_CONF
_dbr_dbm = _helper.DBM_PATH
try:
    import tempfile as _tf_dbr
    _dbr_dir = _tf_dbr.mkdtemp()

    # panel.conf parsing: comments, blank lines and stray whitespace are all tolerated.
    _cfgp = os.path.join(_dbr_dir, "panel.conf")
    with open(_cfgp, "w", encoding="utf-8") as _fh:
        _fh.write("# written by install.sh\n\n  db_path = /var/lib/panel/panel.db  \n")
    _helper.PANEL_CONF = _cfgp
    eq("helper: panel.conf parses key=value, ignoring comments and blanks",
       _helper.panel_conf().get("db_path"), "/var/lib/panel/panel.db")

    # A missing conf is an empty dict, not a crash and not a guess.
    _helper.PANEL_CONF = os.path.join(_dbr_dir, "absent.conf")
    eq("helper: a missing panel.conf reads as empty, not a guessed path", _helper.panel_conf(), {})
    check("helper: db-repair refuses to run with no db_path configured",
          _helper.do_panel_db_repair([], None) == 1)

    # A relative path, or one that does not exist, is refused rather than "repaired".
    for _bad in ("relative/panel.db", os.path.join(_dbr_dir, "does-not-exist.db")):
        with open(_cfgp, "w", encoding="utf-8") as _fh:
            _fh.write("db_path=%s\n" % _bad)
        _helper.PANEL_CONF = _cfgp
        check("helper: db-repair refuses db_path %r" % _bad,
              _helper.do_panel_db_repair([], None) == 1)

    # With a real database configured but NO root-owned db_maintenance beside the helper, it must
    # still refuse — running the checkout's copy is precisely what this verb exists to avoid.
    _realdb = os.path.join(_dbr_dir, "panel.db")
    open(_realdb, "wb").close()
    with open(_cfgp, "w", encoding="utf-8") as _fh:
        _fh.write("db_path=%s\n" % _realdb)
    _helper.PANEL_CONF = _cfgp
    _helper.DBM_PATH = os.path.join(_dbr_dir, "not-installed.py")
    check("helper: db-repair refuses when db_maintenance is not installed root-owned",
          _helper.do_panel_db_repair([], None) == 1)
finally:
    _helper.PANEL_CONF = _dbr_conf
    _helper.DBM_PATH = _dbr_dbm

def _module_toplevel_names(path):
    """Every name a module defines or imports at top level, by AST — no importing.

    Importing a panel module to ask `dir()` would boot eventlet, threads and a Flask app; this only
    needs to know what names EXIST, which the syntax tells us."""
    out = set()
    try:
        _t = _ast_scan.parse(open(path, encoding="utf-8").read())
    except (SyntaxError, OSError):
        return out
    for _n in _t.body:
        if isinstance(_n, (_ast_scan.FunctionDef, _ast_scan.AsyncFunctionDef, _ast_scan.ClassDef)):
            out.add(_n.name)
        elif isinstance(_n, _ast_scan.Assign):
            for _t2 in _n.targets:
                if isinstance(_t2, _ast_scan.Name):
                    out.add(_t2.id)
                elif isinstance(_t2, (_ast_scan.Tuple, _ast_scan.List)):
                    for _e in _t2.elts:
                        if isinstance(_e, _ast_scan.Name):
                            out.add(_e.id)
        elif isinstance(_n, _ast_scan.ImportFrom):
            for _a in _n.names:
                out.add(_a.asname or _a.name)
        elif isinstance(_n, _ast_scan.Import):
            for _a in _n.names:
                out.add((_a.asname or _a.name).split(".")[0])
    return out


# ── A stub must land on the module that RESOLVES the name ─────────────────────────────────────
# `mod.name = fake` on a module that has no `name` creates a NEW attribute and returns quietly. If
# the real function lives elsewhere, the stub never takes effect and the harness measures — or
# tests — un-stubbed code while looking like it worked.
#
# This is not hypothetical. Splitting monitoring out of app.py left four stubs in tools/perf_bench.py
# pointing at app's re-exports while _monitor_pass resolved the names in its own namespace; combined
# with a lost setup_complete flag, the benchmark spent every run timing a 199-byte redirect to
# /setup and printing a table that looked entirely plausible.
#
# READS of a missing attribute already fail loudly with AttributeError. Assignments do not, so
# those are what this checks.
_stub_mods = {}
for _f in sorted(os.listdir(_root)):
    if _f.endswith(".py"):
        _stub_mods[_f[:-3]] = _module_toplevel_names(os.path.join(_root, _f))
_stub_bad = []
for _f in sorted(glob.glob(os.path.join(_root, "tests", "*.py"))
                 + glob.glob(os.path.join(_root, "tools", "*.py"))):
    _src = open(_f, encoding="utf-8").read()
    try:
        _tree = _ast_scan.parse(_src)
    except SyntaxError:
        continue
    _alias = {}
    for _n in _ast_scan.walk(_tree):
        if isinstance(_n, _ast_scan.Import):
            for _a in _n.names:
                _base = _a.name.split(".")[0]
                if _base in _stub_mods:
                    _alias[_a.asname or _base] = _base
        elif isinstance(_n, _ast_scan.Assign) and isinstance(_n.value, _ast_scan.Subscript):
            if (getattr(getattr(_n.value, "value", None), "attr", "") == "modules"
                    and isinstance(_n.value.slice, _ast_scan.Constant)
                    and _n.value.slice.value in _stub_mods):
                for _t in _n.targets:
                    if isinstance(_t, _ast_scan.Name):
                        _alias[_t.id] = _n.value.slice.value
    for _n in _ast_scan.walk(_tree):
        if not (isinstance(_n, _ast_scan.Attribute) and isinstance(_n.ctx, _ast_scan.Store)):
            continue
        if not isinstance(_n.value, _ast_scan.Name):
            continue
        _mod = _alias.get(_n.value.id)
        if not _mod or _n.attr.startswith("__"):
            continue
        # nosudo_runner plants _real_subprocess as a MARKER the module is meant not to have; it is
        # read back with getattr(..., None). That is the one legitimate case.
        if _n.attr == "_real_subprocess":
            continue
        if _n.attr not in _stub_mods[_mod]:
            _stub_bad.append("%s:%d %s.%s (%s has no such name)"
                             % (os.path.basename(_f), _n.lineno, _n.value.id, _n.attr, _mod))
check("every stub is installed on a module that actually defines the name",
      not _stub_bad, "; ".join(sorted(set(_stub_bad))[:4]))

# ── The installer must not build a SECOND panel beside an existing one ────────────────────────
# IS_UPDATE asks "is there an app.py and a unit file where I am about to install?" — but where that
# is has already been decided by how the script was invoked. Run as root it looks under the service
# user's home; run as yourself, under yours. Neither sees the other, so `sudo ./install.sh` on a
# host with a working per-user install found nothing, called it a fresh install, and would have
# built a parallel panel: its own user, service, database and port.
_inst_guard = open(os.path.join(_root, "install.sh"), encoding="utf-8").read()
check("install.sh: looks for an install in the OTHER service model before choosing one",
      "_other_install" in _inst_guard)
check("install.sh: that check runs BEFORE the mode decision, not after",
      _inst_guard.index("_other_install=") < _inst_guard.index('    RUN_AS_ROOT=1'))
check("install.sh: refuses rather than adopting the other install",
      "Refusing to build a parallel install." in _inst_guard)
# The service user's OWN directory must not trip it, or a root install could never update itself.
check("install.sh: skips the service user's own home when scanning for a per-user install",
      '[ "${_u}" = "${SERVICE_USER}" ] && continue' in _inst_guard)
# A stray checkout is not an install; requiring the unit file keeps the check specific.
check("install.sh: requires a user UNIT file, not just an app.py, to call it an install",
      ".config/systemd/user/linuxgsm-panel.service" in _inst_guard)

# ── The sudoers grant itself ──────────────────────────────────────────────────────────────────
# The whole point of the verb table. install.sh writes a NARROW grant when every root-owned piece
# is in place, and the wide one otherwise — because a host that has the new code but has not had
# install.sh re-run as root still falls back to `sudo bash -c '<verb as text>'`, and narrowing
# under it would break every privileged action rather than secure anything.
_inst = open(os.path.join(_root, "install.sh"), encoding="utf-8").read()
check("install.sh: writes a narrow grant permitting only the helper",
      'NOPASSWD: ${HELPER_DST}" > /etc/sudoers.d/linuxgsm-panel' in _inst)
check("install.sh: the narrow grant is conditional on the root-owned pieces being installed",
      '[ "${HELPER_OK}" -eq 1 ] && [ "${ROOT_TOOLS_OK}" -eq 1 ]' in _inst)
check("install.sh: still validates whichever grant it wrote with visudo",
      "visudo -cf /etc/sudoers.d/linuxgsm-panel" in _inst)
# The narrow grant must not quietly re-admit any of the things that were call sites. Each of these
# runs whatever argv you hand it, so permitting one is permitting everything.
_narrow = _inst[_inst.index('if [ "${HELPER_OK}"'):_inst.index("chmod 440 /etc/sudoers.d")]
for _never in ("systemd-run", "/bin/bash", "/bin/sh", "tailscale", "sudo -u"):
    check("install.sh: the narrow grant does not permit %s" % _never, _never not in _narrow)

# ── The update's snapshot and its rollback, RUN rather than read ──────────────────────────────
# The snapshot is the only thing standing between a failed update and a dead install, and its
# check was `[ -s ... ]` — non-empty. The failure the comment beside it names by name is the disk
# filling mid-write, which produces a TRUNCATED archive: non-empty, so it passed. The rollback
# then wiped PANEL_DIR of everything but data/ and venv/ and fed that stream to `tar -xzf` as the
# ONE bare command in the whole failure path — so `set -e` killed the script right there, past
# install_deps, past the service restart and past BOTH die messages, leaving a half-populated
# install and no explanation. The in-panel self-update only watches the log, so nobody is told.
#
# Both halves are EXTRACTED FROM install.sh and executed here. A reimplementation of them would
# pass whatever install.sh actually says.
import subprocess as _sh_sub
from shlex import quote as _shlex_q
_inst_txt = open(os.path.join(_root, "install.sh"), encoding="utf-8").read()
_snap_fn = [ln for ln in _inst_txt.splitlines() if ln.strip().startswith("snapshot_ok() {")]
check("install.sh: the snapshot check is a named function this test can run",
      len(_snap_fn) == 1, str(_snap_fn))
_rb_start = '    if ! tar -C "${PANEL_DIR}" -xzf "${BACKUP}/code.tgz"; then'
check("install.sh: the rollback's unpack is guarded, not bare",
      _rb_start in _inst_txt and 'tar -C "${PANEL_DIR}" -xzf "${BACKUP}/code.tgz"\n' not in _inst_txt)
if _snap_fn and _rb_start in _inst_txt:
    _rb_i = _inst_txt.index(_rb_start)
    _rb_block = _inst_txt[_rb_i:_inst_txt.index("\n    fi\n", _rb_i) + len("\n    fi\n")]

    def _run_snip(body, panel_dir, backup):
        script = ("set -euo pipefail\n"
                  'die() { echo "DIE: $*"; exit 1; }\n'
                  'PANEL_DIR=%s\nBACKUP=%s\n' % (_shlex_q(panel_dir), _shlex_q(backup))
                  + body + "\necho REACHED_END\n")
        return _sh_sub.run(["bash", "-c", script], capture_output=True, text=True)

    _sb = _tempfile.mkdtemp(prefix="inst-rollback-")
    _pd, _bk_dir = os.path.join(_sb, "panel"), os.path.join(_sb, "backup")
    os.makedirs(os.path.join(_pd, "data"))
    os.makedirs(os.path.join(_pd, "venv"))
    os.makedirs(_bk_dir)
    for _f in ("app.py", "manage.py"):
        with open(os.path.join(_pd, _f), "w", encoding="utf-8") as _fh:
            _fh.write("# %s\n" % _f)
    _sh_sub.run(["tar", "-C", _pd, "--exclude=./venv", "--exclude=./data", "-czf",
                 os.path.join(_bk_dir, "good.tgz"), "."], check=True)
    _good = open(os.path.join(_bk_dir, "good.tgz"), "rb").read()
    # A snapshot truncated by a disk filling mid-write: non-empty, unreadable.
    with open(os.path.join(_bk_dir, "code.tgz"), "wb") as _fh:
        _fh.write(_good[:max(64, len(_good) // 3)])
    _snap_body = _snap_fn[0].strip() + '\nsnapshot_ok "${BACKUP}/code.tgz" || die "empty or unreadable"'
    _r = _run_snip(_snap_body, _pd, _bk_dir)
    check("install.sh: a TRUNCATED snapshot is refused (it is non-empty, which -s called fine)",
          _r.returncode == 1 and "DIE:" in _r.stdout and "REACHED_END" not in _r.stdout,
          "%s %r" % (_r.returncode, _r.stdout))
    _r = _run_snip(_snap_fn[0].strip() + '\nsnapshot_ok "${BACKUP}/good.tgz" || die "no"', _pd, _bk_dir)
    check("install.sh: ...and a good one still passes",
          _r.returncode == 0 and "REACHED_END" in _r.stdout, "%s %r" % (_r.returncode, _r.stdout))
    # The rollback itself, against that truncated snapshot: it must DIE with an explanation, not
    # be killed by set -e in the middle.
    _r = _run_snip(_rb_block, _pd, _bk_dir)
    check("install.sh: a rollback that cannot unpack says so instead of dying silently",
          _r.returncode == 1 and "DIE:" in _r.stdout and "INCOMPLETE" in _r.stdout
          and "REACHED_END" not in _r.stdout, "%s %r %r" % (_r.returncode, _r.stdout, _r.stderr))
    check("install.sh: ...and the message names the snapshot the operator has to restore by hand",
          "code.tgz" in _r.stdout, repr(_r.stdout))
    # Control: a good snapshot rolls back and carries on to the rest of the failure path.
    _sh_sub.run(["cp", os.path.join(_bk_dir, "good.tgz"), os.path.join(_bk_dir, "code.tgz")],
                check=True)
    os.remove(os.path.join(_pd, "app.py"))
    _r = _run_snip(_rb_block, _pd, _bk_dir)
    check("install.sh: a good snapshot rolls back and execution continues past it",
          _r.returncode == 0 and "REACHED_END" in _r.stdout
          and os.path.exists(os.path.join(_pd, "app.py")), "%s %r" % (_r.returncode, _r.stdout))
    _shutil.rmtree(_sb, ignore_errors=True)

# ROOT_TOOLS_OK is what write_sudoers_grant reads, and its own comment says it means "every
# root-owned piece is in place … the helper, db_maintenance, and the root-owned installer". It was
# set on the db_maintenance install alone: the panel.conf write was an unchecked && chain whose
# status was discarded, and the installer copy carried `|| true`. A narrow grant could be written
# on a host missing either.
_rt_lines = _inst_txt.splitlines()
_rt_set = [i for i, ln in enumerate(_rt_lines) if ln.strip() == "ROOT_TOOLS_OK=1"]
check("install.sh: ROOT_TOOLS_OK is set in exactly one place", len(_rt_set) == 1, str(_rt_set))
if len(_rt_set) == 1:
    _rt_guard = _rt_lines[_rt_set[0] - 1].strip()
    check("install.sh: ...and only once panel.conf AND the root-owned installer both landed",
          _rt_guard == 'if [ "${CONF_OK}" -eq 1 ] && [ "${INST_OK}" -eq 1 ]; then', _rt_guard)
    check("install.sh: the installer copy records its own success rather than `|| true`",
          '"${INSTALLER_SRC}" "${INSTALLER_DST}" 2>/dev/null && INST_OK=1' in _inst_txt)

# ── panel-self-update: what root executes out of a directory the panel owns ────────────────────
# `panel-self-update` runs the root-owned install.sh as root with cwd=PANEL_DIR, and its docstring
# argues the ROOT-run part is "fixed and small". Three lines said otherwise, and a compromised
# panel reaches all three by writing into its own checkout and calling the verb:
#
#   [2/6]  root ran ${PANEL_DIR}/venv/bin/python3 on ${PANEL_DIR}/db_maintenance.py — a
#          panel-owned interpreter on a panel-owned script, BEFORE any git fetch, so nothing
#          about it is "the new code we verified". Arbitrary root execution, no update involved.
#   deps   root ran the panel-owned venv pip against the panel-owned requirements.txt, and pip
#          executes setup.py and wheel hooks.
#   root   install_root_tools copies ${PANEL_DIR}/tools/panel-helper over the path the sudoers
#   tools  rule names — root replacing the privilege boundary with a file from the checkout.
#          `git reset --hard origin/<branch>` overwrites the checkout first, but `origin` lives in
#          the panel-owned .git/config and _gitc runs git AS THE CHECKOUT OWNER.
#
# All three are EXTRACTED from install.sh and run here, with id/sudo/stat/python3 shimmed so
# nothing escalates: what is asserted is the argv that would have run.
import shlex as _su_shlex
_su_txt = open(os.path.join(_root, "install.sh"), encoding="utf-8").read()


def _su_between(start, end):
    i = _su_txt.index(start)
    j = _su_txt.index(end, i)
    return _su_txt[i:j + len(end)]


def _su_run(body, env_lines, extra=""):
    return _sh_sub.run(["bash", "-c", "set -uo pipefail\nwarn() { echo \"WARN $*\"; }\n"
                        + extra + env_lines + body], capture_output=True, text=True)


_su_sb = _tempfile.mkdtemp(prefix="selfupdate-")
try:
    os.makedirs(os.path.join(_su_sb, "panel", "venv", "bin"))
    open(os.path.join(_su_sb, "panel", "venv", "bin", "python3"), "w").close()
    import stat as _su_stat
    os.chmod(os.path.join(_su_sb, "panel", "venv", "bin", "python3"),
             _su_stat.S_IRWXU)
    open(os.path.join(_su_sb, "panel", "db_maintenance.py"), "w").close()
    os.makedirs(os.path.join(_su_sb, "rootlib"))
    open(os.path.join(_su_sb, "rootlib", "db_maintenance.py"), "w").close()
    _su_env = "PANEL_DIR=%s\n" % _su_shlex.quote(os.path.join(_su_sb, "panel"))

    _su_dbm = _su_between('    DBM_RUN=""', '    fi\n    if [ -n "${DBM_RUN}" ]; then')
    _su_dbm = _su_dbm.rsplit("    if [ -n", 1)[0] + '\necho "DBM_RUN=${DBM_RUN}"\n'
    _su_real = _su_dbm.replace("/usr/local/lib/linuxgsm-panel/db_maintenance.py",
                               os.path.join(_su_sb, "rootlib", "db_maintenance.py"))
    _su_gone = _su_dbm.replace("/usr/local/lib/linuxgsm-panel/db_maintenance.py",
                               os.path.join(_su_sb, "nope.py"))
    _r = _su_run(_su_real, _su_env, extra="id() { echo 0; }\n").stdout.strip()
    check("install.sh: as ROOT, db maintenance is the root-owned script under the system python",
          _r == "DBM_RUN=python3 %s" % os.path.join(_su_sb, "rootlib", "db_maintenance.py"), _r)
    _r = _su_run(_su_gone, _su_env, extra="id() { echo 0; }\n").stdout.strip()
    check("install.sh: ...and with no root-owned copy it runs NOTHING, rather than the checkout's",
          _r == "DBM_RUN=", _r)
    _r = _su_run(_su_real, _su_env, extra="id() { echo 1000; }\n").stdout.strip()
    check("install.sh: an unprivileged install still uses its own venv (no boundary to cross)",
          _r.endswith("/panel/venv/bin/python3 %s/panel/db_maintenance.py" % _su_sb), _r)

    # pip: as the OWNER on the update path, unchanged on the fresh one (where PANEL_DIR is still
    # root's and the requirements came from a clone of REPO_URL the operator asked for).
    _su_deps = _su_between("install_deps() {", "\n}\n") + "\ninstall_deps\n"
    _su_me = _sh_sub.run(["id", "-un"], capture_output=True, text=True).stdout.strip()
    _su_shim = ("id() { echo 0; }\n"
                "stat() { echo %s; }\n"
                "sudo() { echo \"SUDO $*\"; }\n"
                "python3() { echo \"python3 $*\"; }\n")
    _r = _su_run(_su_deps, _su_env + "PANEL_USER=%s\n" % _su_shlex.quote(_su_me),
                 extra=_su_shim % _su_shlex.quote(_su_me)).stdout
    check("install.sh: on the update path pip runs as the checkout's owner, not as root",
          _r.count("SUDO -u %s" % _su_me) >= 2, repr(_r[:200]))
    _r = _su_run(_su_deps, _su_env + "PANEL_USER=%s\n" % _su_shlex.quote(_su_me),
                 extra=_su_shim % "root").stdout
    check("install.sh: ...and the fresh path, where PANEL_DIR is still root's, is unchanged",
          "SUDO" not in _r and "python3 -m venv" in _r, repr(_r[:200]))

    # origin: the URL the root-owned installs are taken from, compared against this file's own
    # REPO_URL — which the panel cannot edit, because install.sh runs from outside the checkout.
    _su_git = os.path.join(_su_sb, "git")
    _sh_sub.run(["git", "init", "-q", _su_git], check=True)
    _su_origin = ('_gitc() { git -C "${PANEL_DIR}" "$@"; }\n'
                  + _su_between("ORIGIN_TRUSTED=1\ncheck_origin_trusted() {", "\n}\n")
                  + '\ncheck_origin_trusted\necho "ORIGIN_TRUSTED=${ORIGIN_TRUSTED}"\n')
    _su_verdicts = []
    for _url, _want in (("https://github.com/FMSMITH91/linuxgsm-panel.git", "1"),
                        ("https://github.com/FMSMITH91/linuxgsm-panel", "1"),
                        ("https://github.com/attacker/evil.git", "0"),
                        ("", "0")):
        _sh_sub.run(["git", "-C", _su_git, "remote", "remove", "origin"], capture_output=True)
        if _url:
            _sh_sub.run(["git", "-C", _su_git, "remote", "add", "origin", _url], check=True)
        _r = _su_run(_su_origin,
                     "PANEL_DIR=%s\nREPO_URL=https://github.com/FMSMITH91/linuxgsm-panel.git\n"
                     % _su_shlex.quote(_su_git)).stdout
        _got = [ln.split("=")[1] for ln in _r.splitlines() if ln.startswith("ORIGIN_TRUSTED=")]
        if not _got or _got[-1] != _want:
            _su_verdicts.append("%s -> %s (want %s)" % (_url or "(unset)", _got, _want))
    check("install.sh: a checkout whose origin is not this repository is not trusted for root installs",
          not _su_verdicts, "; ".join(_su_verdicts))
    # ...and the flag has to actually gate both root-owned steps.
    check("install.sh: install_root_tools returns early when the origin is not trusted",
          'if [ "${ORIGIN_TRUSTED:-1}" -ne 1 ]; then' in _su_txt
          and _su_txt.index('if [ "${ORIGIN_TRUSTED:-1}" -ne 1 ]; then')
          > _su_txt.index("install_root_tools() {"))
    check("install.sh: ...and the sudoers grant is not rewritten from an untrusted checkout",
          '[ "${ORIGIN_TRUSTED}" -eq 1 ] && write_sudoers_grant' in _su_txt)
finally:
    _shutil.rmtree(_su_sb, ignore_errors=True)

# ── The discovery scan, reimplemented in the helper, must speak the parser's dialect ───────────
# discover_linuxgsm_servers used to be a twenty-line shell program run under `sudo bash -c`. It
# needed root for exactly one thing — reading another user's crontab — and everything else was
# ordinary file reading. The helper now does it in Python, so the output contract is the ONLY thing
# holding the two halves together: FOUND|user|instance|port|backups|mods|cronlines|autostart, which
# ssh_manager splits and requires at least 8 fields of.
import tempfile as _tf_disc
_disc_home = _tf_disc.mkdtemp()
_disc_out = []
_sv_home_root, _sv_disc_stdout = _helper.HOME_ROOT, _helper.sys.stdout
try:
    _u = os.path.join(_disc_home, "csgoserver")
    os.makedirs(os.path.join(_u, "lgsm", "config-lgsm", "csgoserver"))
    os.makedirs(os.path.join(_u, "lgsm", "backup"))
    os.makedirs(os.path.join(_u, "lgsm", "mods"))
    with open(os.path.join(_u, "lgsm", "config-lgsm", "csgoserver", "csgoserver.cfg"), "w") as _fh:
        _fh.write("port=27015\n")
    for _b in ("a.tar.gz", "b.tgz", "notes.txt"):
        open(os.path.join(_u, "lgsm", "backup", _b), "w").close()
    with open(os.path.join(_u, "lgsm", "mods", "installed-mods.txt"), "w") as _fh:
        _fh.write("metamod\nsourcemod\n")
    _launcher = os.path.join(_u, "csgoserver")
    open(_launcher, "w").close()
    os.chmod(_launcher, 0o755)

    class _DiscCap:
        def write(self, t):
            _disc_out.append(t)

        def flush(self):
            pass

    _helper.HOME_ROOT = _disc_home
    _helper.sys.stdout = _DiscCap()
    _rc_disc = _helper.do_lgsm_discover([], None)
finally:
    _helper.HOME_ROOT, _helper.sys.stdout = _sv_home_root, _sv_disc_stdout
    import shutil as _sh_disc
    _sh_disc.rmtree(_disc_home, ignore_errors=True)

_disc_line = "".join(_disc_out).strip()
check("helper: lgsm-discover emits a FOUND line for an installed instance",
      _disc_line.startswith("FOUND|"), repr(_disc_line[:120]))
_disc_parts = _disc_line.split("|")
check("helper: lgsm-discover emits the 8 fields ssh_manager splits on",
      len(_disc_parts) >= 8, "%d fields: %r" % (len(_disc_parts), _disc_line[:120]))
if len(_disc_parts) >= 8:
    eq("helper: lgsm-discover reports the user", _disc_parts[1], "csgoserver")
    eq("helper: lgsm-discover reports the instance", _disc_parts[2], "csgoserver")
    eq("helper: lgsm-discover reads the port out of the .cfg", _disc_parts[3], "27015")
    eq("helper: lgsm-discover counts only archive backups, not notes.txt", _disc_parts[4], "2")
    eq("helper: lgsm-discover counts installed mods", _disc_parts[5], "2")

# ── The backup download DROPS privilege; it must never read as root ────────────────────────────
# `sudo -u <user> cat` got one thing exactly right: the read happened as the GAME user, so a
# symlink planted at that path could only reach what that user could already read. Moving it behind
# a root helper is a privilege reduction ONLY if that property survives — read it as root instead
# and a download button becomes "hand me any file on the box".
# ── Every shell script is shellchecked, and panel-helper is linted at all ──────────────────────
# Two blind spots, found by auditing coverage BY FILE TYPE rather than by tool:
#
#   1. shellcheck was given a hand-kept list of five scripts. tools/smoke-local.sh and
#      .clusterfuzzlite/build.sh were never in it. run-tests.sh now derives the list from
#      `git ls-files '*.sh'`; this proves the two lists agree.
#   2. tools/panel-helper is Python with a shebang and NO .py extension, so compileall, flake8 and
#      `bandit -r .` — all of which glob *.py — skipped it entirely. It is the ROOT-OWNED end of
#      the sudo boundary. The most security-critical file in the repo was the one file no static
#      analyser looked at. It is now named explicitly in all three.
_rt_src = open(os.path.join(_root, "tools", "run-tests.sh"), encoding="utf-8").read()
_bandit_src = open(os.path.join(_root, ".github", "workflows", "security-code.yml"),
                   encoding="utf-8").read()
check("coverage: shellcheck's file list is derived from git, not hand-kept",
      "git ls-files '*.sh'" in _rt_src)
check("coverage: panel-helper is byte-compiled (compileall globs *.py and would miss it)",
      "py_compile tools/panel-helper" in _rt_src)
# The flake8 invocation is line-continued, so match the argument list rather than a single line.
_flake_inv = " ".join(l.strip().rstrip("\\") for l in _rt_src.splitlines()
                      if "flake8 --select" in l or "--extend-exclude" in l)
check("coverage: panel-helper is flake8'd (its default glob would miss it)",
      "tools/panel-helper" in _flake_inv, _flake_inv[:120])
check("coverage: panel-helper is bandit-scanned (bandit -r . globs *.py and would miss it)",
      "bandit -r . tools/panel-helper" in _bandit_src)
# ...and the file really is Python, so those three tools have something to say about it.
check("coverage: panel-helper is a python script (shebang), justifying the above",
      open(os.path.join(_root, 'tools', 'panel-helper'), encoding='utf-8').readline().startswith("#!") and "python" in open(os.path.join(_root, 'tools', 'panel-helper'), encoding='utf-8').readline())

_gbr = open(os.path.join(_root, "tools", "panel-helper"), encoding="utf-8").read()
_gbr_fn = _gbr[_gbr.index("def do_game_backup_read"):]
_gbr_fn = _gbr_fn[:_gbr_fn.index("\ndef ", 1)]
for _need, _why in (("os.setgroups([])", "supplementary groups are cleared"),
                    ("os.setgid(pw.pw_gid)", "gid is dropped"),
                    ("os.setuid(pw.pw_uid)", "uid is dropped")):
    check("helper: game-backup-read %s" % _why, _need in _gbr_fn, _need)
check("helper: game-backup-read drops the gid BEFORE the uid (the reverse cannot work)",
      _gbr_fn.index("os.setgid(") < _gbr_fn.index("os.setuid("))
check("helper: game-backup-read verifies the drop took before opening anything",
      "os.getuid() != pw.pw_uid" in _gbr_fn
      and _gbr_fn.index("os.getuid() != pw.pw_uid") < _gbr_fn.index("open(path"))
check("helper: game-backup-read opens the file only in the CHILD, after the drop",
      _gbr_fn.index("os.fork()") < _gbr_fn.index("open(path"))

# ── The restore swap: staging location and destinations both come from root's config ──────────
# do_panel_restore takes ZERO arguments for the same reason do_panel_db_repair does, but the stakes
# are higher here: the copy targets are the panel's database AND both encryption keys. A verb that
# accepted a staging path would let a caller name a directory it cannot itself read (say
# /etc/ssl/private) and have root copy the contents somewhere it can.
_rst_conf = _helper.PANEL_CONF
try:
    import tempfile as _tf_rst
    _rst_dir = _tf_rst.mkdtemp()
    _rst_cfg = os.path.join(_rst_dir, "panel.conf")

    _helper.PANEL_CONF = os.path.join(_rst_dir, "absent.conf")
    check("helper: restore refuses with no data_dir configured",
          _helper.do_panel_restore([], None) == 1)

    for _bad in ("relative/data", os.path.join(_rst_dir, "not-a-dir")):
        with open(_rst_cfg, "w", encoding="utf-8") as _fh:
            _fh.write("data_dir=%s\n" % _bad)
        _helper.PANEL_CONF = _rst_cfg
        check("helper: restore refuses data_dir %r" % _bad,
              _helper.do_panel_restore([], None) == 1)

    # A real data_dir but nothing staged must refuse too — otherwise a stray call would stop the
    # panel, copy nothing, and start it again for no reason.
    _real = os.path.join(_rst_dir, "data")
    os.makedirs(_real, exist_ok=True)
    with open(_rst_cfg, "w", encoding="utf-8") as _fh:
        _fh.write("data_dir=%s\n" % _real)
    _helper.PANEL_CONF = _rst_cfg
    check("helper: restore refuses when nothing is staged",
          _helper.do_panel_restore([], None) == 1)
finally:
    _helper.PANEL_CONF = _rst_conf

check("helper: the restore staging directory is a fixed NAME, not a caller argument",
      _helper.RESTORE_STAGE == ".restore-stage"
      and _helper.VERBS["panel-restore"][0] == [])
check("helper: restore copies exactly the four known members",
      _helper.RESTORE_MEMBERS == ("panel.db", "config.json", "secret_key", "cred_key"))

# db_maintenance.repair must work from an explicit path — that is what lets a ROOT-OWNED copy run
# under the system interpreter without importing the panel's config out of the checkout.
check("db_maintenance: repair runs from an explicit path, no config import",
      "argv[2]" in open(os.path.join(_root, "db_maintenance.py"), encoding="utf-8").read())

# ── register_routes is shrinking, and helpers do not drift back into it ──────────────────────
# register_routes() was 6,570 lines holding 206 views AND 54 helper functions the views closed
# over. Those closures are the reason the route table could not be split into modules: no view can
# move out while a helper it calls is trapped in that scope. Hoisting them is the precondition, so
# this RATCHETS — the helper count inside may fall and never rise, exactly like the escalation
# census. tests/url_map_baseline.json is what proves a move changed no route.
import ast as _ast_rr
# DERIVED, not a number to remember to bump. Counting the views that actually live in
# panel/routes/*.py means the sum can only be wrong if a view really went missing — a hand-kept
# constant would drift the first time someone moved a section and forgot, which is exactly the
# bookkeeping this check exists to replace.
_MOVED_VIEWS = 0
_routes_dir = os.path.join(_root, "panel", "routes")
if os.path.isdir(_routes_dir):
    for _rf in sorted(os.listdir(_routes_dir)):
        if not _rf.endswith(".py") or _rf == "__init__.py":
            continue
        _rt = _ast_rr.parse(open(os.path.join(_routes_dir, _rf), encoding="utf-8").read())
        _MOVED_VIEWS += sum(
            1 for _n in _ast_rr.walk(_rt)
            if isinstance(_n, _ast_rr.FunctionDef)
            and any(isinstance(_d, _ast_rr.Call) and getattr(_d.func, "attr", "") == "route"
                    for _d in _n.decorator_list))
_app_ast = _ast_rr.parse(open(os.path.join(_root, "app.py"), encoding="utf-8").read())
_rr = next(n for n in _ast_rr.walk(_app_ast)
           if isinstance(n, _ast_rr.FunctionDef) and n.name == "register_routes")
_rr_defs = [n for n in _rr.body if isinstance(n, _ast_rr.FunctionDef)]
_rr_views = [n for n in _rr_defs
             if any(isinstance(d, _ast_rr.Call) and getattr(d.func, "attr", "") == "route"
                    for d in n.decorator_list)]
_rr_helpers = len(_rr_defs) - len(_rr_views)
_HELPER_CEILING = 20   # ratcheted down as sections moved to panel/routes/
check("register_routes: helper closures inside it <= %d (currently %d)"
      % (_HELPER_CEILING, _rr_helpers),
      _rr_helpers <= _HELPER_CEILING,
      "it went UP — a new helper belongs at module level, not nested in the route table")
# 220, was 219: /api/server/<id>/log-timestamps is a genuinely new view — it reads and sets
# LinuxGSM's own `logtimestamp`, which stamps the console log AT WRITE TIME. That is the only way a
# line written while nobody was watching can carry a real time; the panel tails the file and can
# otherwise date only what it saw arrive.
# 219, was 218: /api/server/<id>/version is a genuinely new view — which build of the game is
# installed (the Steam manifest on disk, plus the version the running game reports). Its own
# endpoint rather than a field on /stats, which polls every few seconds: this costs an SSH read
# and a game query, and the answer only moves when an update runs.
# 217, was 216: /users/invite/<id>/revoke — an invite could be minted but not taken back, so a
# link sent to the wrong address could only be waited out (up to the 30-day max TTL).
# 218, was 217: /servers/install is a genuinely new view — the install form moved off
# /servers/manage onto its own page, because it sat above the list of servers you already have and
# put that list 1.11 screens down on a phone. Same permission pair as the POST it submits to.
# 216, was 214: two genuinely new views — /api/remote/<id>/firewall/limit (UFW rate limiting was
# reachable from the privileged layer but from no route) and /firewall/allow-from (a port open
# only from one address or network, which no verb could express before).
# 214, was 212: two genuinely new views for one-time invite links — /users/invite mints one
# (superadmin only) and /invite/<token> redeems it. The redemption route is deliberately NOT
# login_required: creating your own account is the whole point of the link.
# 212, was 211: /account/profile is a genuinely new view — it lets someone change their OWN
# display name, which previously only an admin could do through Manage Users.
# 211, was 210: /password/change is a genuinely new view (the page an account with an admin-issued
# password is held on until it sets its own). This total exists to catch a view VANISHING during a
# move, so adding one is a deliberate bump — and url_map_baseline.json's diff is the record of what
# the new route actually is.
check("register_routes: every one of the 220 views is still accounted for",
      len(_rr_views) + _MOVED_VIEWS == 220,
      "views inside=%d, moved out=%d" % (len(_rr_views), _MOVED_VIEWS))
# These two use current_app, which only equals the closed-over `app` inside a request — every
# caller is a view, so that holds. If they drift back inside a closure, the reasoning stops being
# checked. They are no longer app.py's at all: they moved to panel/core/http.py with the rest of
# the pure layer, so the assertion follows them there AND still refuses to see them nested in
# register_routes — which is the half that actually guards the current_app reasoning.
_http_ast = _ast_rr.parse(
    open(os.path.join(_root, "panel", "core", "http.py"), encoding="utf-8").read())
for _h in ("_log_and_generic", "_unreachable"):
    check("panel/core/http.py: %s is module-level" % _h,
          any(isinstance(n, _ast_rr.FunctionDef) and n.name == _h for n in _http_ast.body),
          "it is not a top-level def there")
    check("register_routes: %s did not drift back into a closure" % _h,
          not any(isinstance(n, _ast_rr.FunctionDef) and n.name == _h
                  for n in _ast_rr.walk(_rr)),
          "it reappeared inside register_routes")

# ── Every file in data/ that holds DB rows or keys is hardened ───────────────────────────────
# harden_data_permissions() covered the DB, its WAL/SHM pair, the config and both keys — but not
# data/panel.db.backup, the rolling known-good copy models._ensure_db_healthy refreshes on every
# healthy start, nor the panel.db.corrupt-* copies it moves aside. Both hold every password hash
# and every encrypted credential the live database does, and sqlite3.connect / shutil.copy2 create
# them at the process umask (0644 on a stock box). data/ is 0700 so this was defence in depth
# rather than exposure, but it was the one gap in a function whose whole job is not having one.
import tempfile as _tf
import stat as _st
from panel.core import config as _cfgm
_hd_tmp = _tf.mkdtemp()
_hd_saved = (_cfgm.DATA_DIR, _cfgm.DB_PATH, _cfgm.CONFIG_FILE, _cfgm.SECRET_FILE, _cfgm.CRED_KEY_FILE)
try:
    from pathlib import Path as _P
    _cfgm.DATA_DIR = _P(_hd_tmp)
    _cfgm.DB_PATH = _P(_hd_tmp) / "panel.db"
    _cfgm.CONFIG_FILE = _P(_hd_tmp) / "config.json"
    _cfgm.SECRET_FILE = _P(_hd_tmp) / "secret_key"
    _cfgm.CRED_KEY_FILE = _P(_hd_tmp) / "cred_key"
    _hd_files = ("panel.db", "panel.db-wal", "panel.db-shm", "panel.db.backup",
                 "panel.db.corrupt-1700000000", "config.json", "secret_key", "cred_key")
    for _n in _hd_files:
        _fp = _P(_hd_tmp) / _n
        _fp.write_bytes(b"x")
        os.chmod(_fp, 0o644)
    _cfgm.harden_data_permissions()
    _hd_bad = [_n for _n in _hd_files
               if _st.S_IMODE(os.stat(os.path.join(_hd_tmp, _n)).st_mode) != 0o600]
    check("data perms: every sensitive file in data/ ends up 0600", not _hd_bad,
          "left readable: %s" % _hd_bad)
finally:
    (_cfgm.DATA_DIR, _cfgm.DB_PATH, _cfgm.CONFIG_FILE,
     _cfgm.SECRET_FILE, _cfgm.CRED_KEY_FILE) = _hd_saved
    import shutil as _sh
    _sh.rmtree(_hd_tmp, ignore_errors=True)

# ── The self-signed TLS key is created 0600, never written then chmod'd ──────────────────────
# The old order wrote the unencrypted private key at the process umask and tightened it after,
# leaving a window in which it was world-readable.
from panel.services import certs as _certs
_ck_tmp = _tf.mkdtemp()
try:
    _ck_cert = os.path.join(_ck_tmp, "ssl", "cert.pem")
    _ck_key = os.path.join(_ck_tmp, "ssl", "key.pem")
    _certs._ensure_self_signed_cert(_ck_cert, _ck_key, "probe.invalid")
    check("tls: the generated private key is 0600",
          _st.S_IMODE(os.stat(_ck_key).st_mode) == 0o600,
          "mode %o" % _st.S_IMODE(os.stat(_ck_key).st_mode))
    check("tls: ...and it is created that way, not chmod'd afterwards",
          "os.open(key_path" in _modsrc("certs"))
finally:
    _sh.rmtree(_ck_tmp, ignore_errors=True)

# ── The Codacy accepted-errors list is a reviewable list, not a dumping ground ────────────────
# .github/codacy-accepted-errors.json is what stops the "Error-level Codacy issues on main" gate
# failing — so an entry added without a reason is a silent permanent suppression, which is the
# state that gate exists to end. Every entry needs all four fields and a real reason.
_acc_path = os.path.join(_root, ".github", "codacy-accepted-errors.json")
check("codacy: the accepted-errors list exists", os.path.isfile(_acc_path))
if os.path.isfile(_acc_path):
    _acc = json.load(open(_acc_path, encoding="utf-8"))
    _entries = _acc.get("accepted", [])
    _bad = []
    for _e in _entries:
        _missing = [_k for _k in ("filePath", "patternId", "lineText", "reason", "acceptedOn")
                    if not (_e.get(_k) or "").strip()]
        if _missing:
            _bad.append("%s: missing %s" % (_e.get("filePath", "?"), ",".join(_missing)))
        elif len((_e.get("reason") or "").split()) < 12:
            # A one-liner like "false positive" is not a review. Make the bar explicit.
            _bad.append("%s: reason is too short to be a review" % _e.get("filePath"))
    check("codacy: every accepted Error carries a full key and a real reason", not _bad,
          "; ".join(_bad))
    check("codacy: the accepted list is short enough to actually read",
          len(_entries) <= 5, "%d entries — it is meant to shrink" % len(_entries))
    # Keyed on the source LINE, never the line number: a number moves with every edit above it,
    # and one (file, rule) pair covers every hit of that rule in the file — which is how the first
    # draft of this list silently accepted a second, unrelated finding in system_ops.py.
    check("codacy: entries are keyed on the source line, not a line number",
          all("lineNumber" not in _e for _e in _entries) and all("lineText" in _e for _e in _entries))
    _gate = os.path.join(_root, ".github", "scripts", "codacy_open_errors.py")
    check("codacy: the gate script is present and referenced by its workflow",
          os.path.isfile(_gate)
          and "codacy_open_errors.py" in open(
              os.path.join(_root, ".github", "workflows", "codacy-alerts.yml"),
              encoding="utf-8").read())

# ── The docs state numbers that the code owns — pin them ──────────────────────────────────────
# Every one of these was wrong at the time of writing, and none of them could be. SECURITY.md said
# "43 verbs" against 86; the CHANGELOG said 77 in the same release; README advertised 18 alert
# events against 19, and listed `super_admin` as a grantable permission two years after it stopped
# being one. Prose does not enforce itself, so the numbers get gates like everything else.
# SECURITY.md lives in .github/ (one of the three locations GitHub reads a security policy
# from — root, docs/, .github/). Resolved rather than hardcoded, and RAISING when no copy is
# found, so moving it between those three turns this red instead of skipping the gate.
def _docsrc(leaf):
    """Source text of a repo doc, wherever GitHub allows it to live. Raises if absent."""
    for _cand in (leaf, os.path.join(".github", leaf), os.path.join("docs", leaf)):
        _fp = os.path.join(_root, _cand)
        if os.path.exists(_fp):
            return open(_fp, encoding="utf-8").read()
    raise FileNotFoundError("no %s in ./, .github/ or docs/ — a docs gate lost its subject" % leaf)


_sec = _docsrc("SECURITY.md")
_readme = open(os.path.join(_root, "README.md"), encoding="utf-8").read()

check("docs: SECURITY.md states the real verb count",
      "%d verbs" % len(_privmod.verbs()) in _sec,
      "table has %d; SECURITY.md says %s"
      % (len(_privmod.verbs()),
         (re.search(r"(\d+) verbs", _sec) or ["?", "?"])[1]))
check("docs: README states the real number of alert events",
      "%d events" % len(N.EVENTS) in _readme,
      "EVENTS has %d; README says %s"
      % (len(N.EVENTS), (re.search(r"for (\d+) events", _readme) or ["?", "?"])[1]))
# The systemd unit list in SECURITY.md must name every unit the verb table actually accepts.
check("docs: SECURITY.md's systemd unit list matches privileged.UNITS",
      all(("`%s`" % _u) in _sec for _u in _privmod.UNITS),
      "missing from the doc: %s" % [_u for _u in _privmod.UNITS if ("`%s`" % _u) not in _sec])
# super_admin is the is_superadmin FLAG, not a permission. Documenting it as grantable sends an
# operator looking for a tickbox that was deliberately removed.
from panel.security import auth as _authmod
check("docs: README does not offer super_admin as a grantable permission",
      "| `super_admin` |" not in _readme)
check("docs: ...and it really is not one", "super_admin" not in _authmod.ALL_PERMISSIONS)

# Every fuzz harness must be listed in its README and run by the workflow matrix. The README
# documented 4 of 6 (console and cron were missing), which is how a target quietly stops being
# maintained.
_fuzz_dir = os.path.join(_root, "tests", "fuzz")
_harnesses = sorted(os.path.basename(f)[len("fuzz_"):-len(".py")]
                    for f in glob.glob(os.path.join(_fuzz_dir, "fuzz_*.py")))
_fuzz_readme = open(os.path.join(_fuzz_dir, "README.md"), encoding="utf-8").read()
check("docs: every fuzz harness is listed in tests/fuzz/README.md",
      all(("fuzz_%s.py" % t) in _fuzz_readme for t in _harnesses),
      "missing: %s" % [t for t in _harnesses if ("fuzz_%s.py" % t) not in _fuzz_readme])
_fuzz_wf = open(os.path.join(_root, ".github", "workflows", "fuzz.yml"), encoding="utf-8").read()
_matrix = re.search(r"target:\s*\[([^\]]+)\]", _fuzz_wf)
_matrix_targets = sorted(t.strip() for t in _matrix.group(1).split(",")) if _matrix else []
check("docs: the fuzz workflow matrix runs every harness", _matrix_targets == _harnesses,
      "matrix=%s harnesses=%s" % (_matrix_targets, _harnesses))
# ...and each harness's own module must be in the workflow's path filter, or a change to the code
# it tests does not trigger it. terminal.py (fuzz_console's target) was missing for exactly that
# reason.
#
# The expected path is DERIVED from where the module actually is, not written out here. These are
# inclusive `paths:` filters, so a stale entry doesn't fail the workflow — it silently stops
# triggering it, which is the same "quietly stops being maintained" failure this block exists to
# catch. Moving a module now either updates the filter or turns this red.
for _mod in ("ssh_manager.py", "system_ops.py", "terminal.py"):
    _p = _modpath(_mod)
    _want = os.path.relpath(_p, _root).replace(os.sep, "/") + ("/**" if os.path.isdir(_p) else "")
    check("docs: the fuzz workflow watches %s (as '%s')" % (_mod, _want),
          ("'%s'" % _want) in _fuzz_wf, "not in fuzz.yml paths:")

# ── ufw_allow_tailscale builds a VERB, and does not raise ─────────────────────────────────────
# It read `_run("ufw-allow-iface", [iface], timeout=15)` — _run's signature is
# (cmd, timeout=30, sudo=False, text=True), so the list went in as the positional `timeout` AND
# timeout=15 came in by keyword: TypeError on every single call, 100% of the time. The route
# answered 500, and the two automatic callers in tailscale_integration (after `tailscale up`, and
# during Serve setup) swallow exceptions — so the guard whose whole purpose is "don't let UFW lock
# you out of your own tailnet" had silently not run since the verb conversion.
_uat_calls = []
_uat_saved = (SO._run_verb, SO.detect_tailscale_interface)
try:
    SO.detect_tailscale_interface = lambda: "tailscale0"
    SO._run_verb = lambda verb, args=(), timeout=30, merge_stderr=True: (
        _uat_calls.append((verb, list(args))), ("", "", 0))[1]
    _uat_ok, _uat_msg = SO.ufw_allow_tailscale()
    check("ufw_allow_tailscale: does not raise (it used to TypeError on every call)", _uat_ok is True,
          str(_uat_msg))
    check("ufw_allow_tailscale: goes through the verb table, not a shell string",
          _uat_calls == [("ufw-allow-iface", ["tailscale0"])], str(_uat_calls))
finally:
    SO._run_verb, SO.detect_tailscale_interface = _uat_saved
# ...and the verb it names really exists, so a rename cannot leave it calling a dead one.
check("ufw_allow_tailscale: the verb it calls is in the table",
      "ufw-allow-iface" in _privmod.verbs())

# ── X-Forwarded-Prefix is only believed from a proxy we have reason to trust ──────────────────
# PrefixMiddleware read the header unconditionally, on every request, with the panel able to bind
# 0.0.0.0. SCRIPT_NAME is what every url_for() and every outgoing Location is built from, so any
# client could rewrite the links in its own response — including to a protocol-relative "//host".
# auth.client_ip() has always applied exactly this rule to X-Forwarded-For; this brings the other
# forwarded header in line.
from panel.core import middleware as _mw
# ...and the middleware must actually CONSULT it — the helper passing on its own proves nothing
# if __call__ still reads the header unconditionally.
_mw_src = _modsrc("middleware")
_mw_call = _mw_src[_mw_src.index("def __call__"):]
check("prefix header: __call__ gates the header read on _may_trust_header",
      "_may_trust_header" in _mw_call
      and _mw_call.index("_may_trust_header") < _mw_call.index("if not prefix"))
for _ra, _cfg, _want in (("127.0.0.1", {}, True), ("::1", {}, True),
                         ("203.0.113.7", {}, False), ("10.1.2.3", {}, False),
                         ("", {}, False),
                         ("203.0.113.7", {"trust_proxy": True}, True)):
    check("prefix header: REMOTE_ADDR=%r trust_proxy=%s -> trusted=%s"
          % (_ra, bool(_cfg.get("trust_proxy")), _want),
          _mw.PrefixMiddleware._may_trust_header({"REMOTE_ADDR": _ra}, _cfg) is _want)

# A Location is "already prefixed" only when it is the prefix itself or a path UNDER it. The test
# was `v.startswith(prefix)`, which is also true of a path that merely shares the first characters:
# with the panel mounted at /panel, a redirect to /panelserver read as already-prefixed and was
# sent out unchanged, pointing outside the mount — a 404 for the user, and the one thing this
# middleware exists to prevent.
class _MwStart:
    def __init__(self):
        self.headers = None

    def __call__(self, status, headers, *a):
        self.headers = headers


def _mw_location(loc, prefix="/panel"):
    """The Location header a response carries after the middleware has rewritten it."""
    _sr = _MwStart()

    def _app(_environ, start_response):
        start_response("302 FOUND", [("Location", loc)])
        return [b""]

    _mid = _mw.PrefixMiddleware(_app, prefix)
    # Loopback + no X-Forwarded-Prefix, so the mount comes from the constructor argument.
    _mid({"REMOTE_ADDR": "127.0.0.1", "PATH_INFO": "/", "wsgi.url_scheme": "http"}, _sr)
    return dict(_sr.headers).get("Location")

eq("prefix: a path UNDER the mount is left alone", _mw_location("/panel/servers"), "/panel/servers")
eq("prefix: the mount itself is left alone", _mw_location("/panel"), "/panel")
eq("prefix: an unprefixed path gets the mount", _mw_location("/servers"), "/panel/servers")
eq("prefix: a path that merely STARTS WITH the mount is a different path, and gets prefixed",
   _mw_location("/panelserver"), "/panel/panelserver")

# ── The installer refreshes the root-owned helper on an UPDATE, not only a fresh install ──────
# The helper/db_maintenance/panel.conf/installer block used to sit AFTER the update path's
# `exit 0`, so every update — in-panel self-update, the CI auto-deploy, a plain re-run — shipped
# new code against whatever helper first landed on the host. The verb table grows most releases and
# a stale helper answers a new verb with `unknown verb` + rc 2 and no fallback, so the feature
# behind it stopped working with no message anywhere. The grant was never re-evaluated either.
_inst = open(os.path.join(_root, "install.sh"), encoding="utf-8").read()
check("install.sh: the root-owned tools are installed by a FUNCTION, callable from both paths",
      "install_root_tools() {" in _inst and "write_sudoers_grant() {" in _inst)
_upd = _inst[_inst.index("if [ \"${IS_UPDATE}\" -eq 1 ]; then"):]
_upd_body = _upd[:_upd.index("    # ── Health check FAILED")]
check("install.sh: the UPDATE path refreshes the root-owned helper before restarting the service",
      "install_root_tools" in _upd_body
      and _upd_body.index("install_root_tools") < _upd_body.index('info "[5/6] Starting the service'))
check("install.sh: the UPDATE path also re-evaluates the sudoers grant",
      "write_sudoers_grant" in _upd_body)
check("install.sh: the update path still exits before the fresh-install steps",
      "    exit 0\n" in _upd_body)
# The root-owned installer copy must come from the CHECKOUT: the documented quick install is
# `curl … | bash`, where "$0" is the shell — the old form copied /usr/bin/bash into place.
check("install.sh: the root-owned installer copy is sourced from the checkout, not \"$0\"",
      'INSTALLER_SRC="${PANEL_DIR}/install.sh"' in _inst)

# ── Disabling Tailscale Serve removes the mount it is actually ON ─────────────────────────────
# disableServe() hardcoded mount:'/'. `tailscale serve --remove /` exits 0 on a node whose mapping
# is at /lgsm-panel, so the panel reported success, cleared tailscale_setup_done and
# tailscale_mount, and left Serve running — with PrefixMiddleware then no longer prefixing URLs
# for a panel still served under the prefix.
_ts_tpl = open(os.path.join(_root, "templates", "tailscale.html"), encoding="utf-8").read()
check("tailscale.html: disableServe does not hardcode the mount",
      "action: 'disable', mount: '/'" not in _ts_tpl)
check("tailscale.html: the Disable button carries the configured mount",
      'data-mount="{{ config.tailscale_mount' in _ts_tpl)
check("tailscale.html: the Mount Point field shows the configured mount, not a fixed /",
      "value=\"{{ config.tailscale_mount or '/' }}\"" in _ts_tpl)
# Both serve handlers take the clicked button; enableServe used the implicit global `event`.
check("tailscale.html: enableServe/disableServe receive @self rather than reading global event",
      "var btn = event.target" not in _ts_tpl
      and _ts_tpl.count("""data-args='["@self"]'""") >= 2)

# ── Vendored front-end libraries match their manifest ─────────────────────────────────────────
# static/vendor/ holds ~650KB of third-party browser code: Bootstrap, its icons, Chart.js and the
# Socket.IO client. Nothing was managing any of it — Dependabot reads pip and github-actions, there
# is no package.json, and no scanner looks inside a minified bundle. The result was that Bootstrap's
# JS sat at 5.3.0 while its CSS was 5.3.3 for months with nothing able to notice.
#
# static/vendor/VERSIONS.md is the manifest. This asserts it is true: every listed file exists, and
# the version recorded for it is the version in that file's own banner comment. A bump is then a
# deliberate edit to both, and a silent swap fails the build.
_vendor_dir = os.path.join(_root, "static", "vendor")
_manifest = os.path.join(_vendor_dir, "VERSIONS.md")
check("vendor: the manifest exists", os.path.isfile(_manifest))
if os.path.isfile(_manifest):
    _rows = re.findall(r"^\|\s*([^|]+?)\s*\|\s*([0-9][0-9.]*)\s*\|\s*`([^`]+)`\s*\|",
                       open(_manifest, encoding="utf-8").read(), re.M)
    check("vendor: the manifest lists every vendored library", len(_rows) >= 5,
          "found %d rows" % len(_rows))
    # Every vendored .js/.css must appear in the manifest — a new one cannot be added unlisted.
    _on_disk = set()
    for _dirpath, _dirnames, _filenames in os.walk(_vendor_dir):
        for _fn in _filenames:
            if _fn.endswith((".js", ".css")):
                _on_disk.add(os.path.relpath(os.path.join(_dirpath, _fn), _vendor_dir))
    _listed = {r[2] for r in _rows}
    check("vendor: no vendored file is missing from the manifest",
          not (_on_disk - _listed), "unlisted: %s" % sorted(_on_disk - _listed))
    _bad = []
    for _name, _ver, _rel in _rows:
        _path = os.path.join(_vendor_dir, _rel)
        if not os.path.isfile(_path):
            _bad.append("%s: file missing (%s)" % (_name, _rel))
            continue
        # The banner comment is in the first few hundred bytes of every one of these builds.
        with open(_path, encoding="utf-8", errors="replace") as _fh:
            _head = _fh.read(600)
        if _ver not in _head:
            _found = re.search(r"v?(\d+\.\d+\.\d+)", _head)
            _bad.append("%s: manifest says %s, file says %s"
                        % (_name, _ver, _found.group(1) if _found else "?"))
    check("vendor: every file is the version the manifest records", not _bad, "; ".join(_bad))
    # Bootstrap ships its JS and CSS as one release but they are vendored as two files, so they
    # can drift — and did, 5.3.0 JS against 5.3.3 CSS, for months. They were API-compatible so
    # nothing looked broken, which is exactly why nobody caught it. Require them to agree.
    _js = [r for r in _rows if r[0].strip() == "Bootstrap (JS)"]
    _css = [r for r in _rows if r[0].strip() == "Bootstrap (CSS)"]
    check("vendor: Bootstrap's JS and CSS are the same release",
          _js and _css and _js[0][1] == _css[0][1],
          "JS %s vs CSS %s — they ship together and must be vendored together"
          % (_js[0][1] if _js else "?", _css[0][1] if _css else "?"))

# ── One key, one section file ─────────────────────────────────────────────────────────────────
# i18n.catalog() merges translations/<lang>/*.json in sorted FILENAME order, last write wins. That
# order is alphabetical accident, not a decision — so a key present in two files has its translation
# chosen by which file happens to sort later. Three dashboard tile labels were in two files each,
# and two of those pairs DISAGREED: "Players Online" was both "Jugadores conectados" (common.json)
# and "Jugadores en línea" (servers.json), with servers.json winning purely on the "s".
#
# Duplicates are banned outright rather than only conflicting ones: an identical duplicate is the
# state a conflicting one starts from, and the fix for both is the same — put the key in one file.
_i18n_dir = os.path.join(_root, "translations")
for _lang in ("es", "fr"):
    _homes = {}
    for _f in sorted(glob.glob(os.path.join(_i18n_dir, _lang, "*.json"))):
        for _k in json.load(open(_f, encoding="utf-8")):
            _homes.setdefault(_k, []).append(os.path.basename(_f))
    _dupes = {_k: _v for _k, _v in _homes.items() if len(_v) > 1}
    check("i18n (%s): every key lives in exactly one section file" % _lang, not _dupes,
          "; ".join("%r in %s" % (_k, _v) for _k, _v in list(_dupes.items())[:3]))
# ...and the two languages must cover the same keys, or one of them silently falls back to English
# for a phrase the other translates.
_i18n_keys = {}
for _lang in ("es", "fr"):
    _ks = set()
    for _f in glob.glob(os.path.join(_i18n_dir, _lang, "*.json")):
        _ks |= set(json.load(open(_f, encoding="utf-8")))
    _i18n_keys[_lang] = _ks
check("i18n: es and fr translate the same set of keys",
      _i18n_keys["es"] == _i18n_keys["fr"],
      "es-only=%s fr-only=%s" % (sorted(_i18n_keys["es"] - _i18n_keys["fr"])[:3],
                                 sorted(_i18n_keys["fr"] - _i18n_keys["es"])[:3]))

# ── Every user-visible template string is actually IN the catalog ─────────────────────────────
# Nothing in a template is wrapped in t(). base.html hands the browser the catalog and walks the
# DOM, swapping any text node (and title/placeholder/aria-label) whose exact whitespace-collapsed
# text is a key. So a string is translated if and only if it appears in the catalog VERBATIM — and
# nothing failed, anywhere, when it didn't: the page just silently stayed English for a Spanish or
# French user. 313 of 961 strings (33%) were in that state when this gate was written, including
# every label on the Settings page and every Hide/Move control on server_detail.
#
# tools/i18n_scan reproduces the runtime walker's rules exactly rather than approximating them,
# because the two ways of being wrong are both bad: <code> and <pre> ARE skipped at runtime, so
# flagging `<code>sv_maxclients</code>` would demand a pointless translation, and an element's own
# data-no-i18n exempts its placeholder too.
#
# To satisfy this gate, either translate the string in BOTH languages, or — for a technical literal
# that must stay verbatim (a hostname, a hex colour, a brand name) — mark it data-no-i18n.
sys.path.insert(0, os.path.join(_root, "tools"))
import i18n_scan as _i18n_scan  # noqa: E402
_i18n_gaps = _i18n_scan.missing("es",
                                template_dir=os.path.join(_root, "templates"),
                                translation_dir=_i18n_dir)
check("i18n: every translatable template string is in the catalog",
      not _i18n_gaps,
      "%d untranslated: %s" % (len(_i18n_gaps),
                               "; ".join("%r in %s" % (_k, ",".join(sorted(_v)))
                                         for _k, _v in sorted(_i18n_gaps.items())[:4])))

# ...and the same for the strings the JAVASCRIPT builds. Toasts, confirm dialogs and JS-rendered
# labels go through the very same MutationObserver, so they are translated on identical terms —
# which is how the host Specs card came to show "Memory" in Spanish next to "Operating System" in
# English. The scanner only claims a literal that reads as whole prose and is not half of a
# concatenation (that kind reaches the DOM welded to per-request text and no key can match it);
# put `i18n-ignore` in a comment on the line to exempt one it gets wrong.
_i18n_js_gaps = _i18n_scan.missing_js(
    "es", js_dir=os.path.join(_root, "static", "js"), translation_dir=_i18n_dir)
check("i18n: every user-visible string in the JS is in the catalog",
      not _i18n_js_gaps,
      "%d untranslated: %s" % (len(_i18n_js_gaps),
                               "; ".join("%r in %s" % (_k, ",".join(sorted(_v)))
                                         for _k, _v in sorted(_i18n_js_gaps.items())[:4])))

# ── The Tailscale login URL is pinned the same way on both paths ──────────────────────────────
# `tailscale up` prints a login link that the panel renders into an href AND into the link text, on
# two pages. The charset is enforced by a grep running ON THE HOST BEING JOINED, so the panel has to
# re-check the whole string itself. ssh_manager's remote flow did (fullmatch); the panel-host twin in
# tailscale_integration tested only startswith, which accepts anything after the trusted prefix.
from panel.ops import tailscale_integration as _tsi
_tsi_src = _modsrc("tailscale_integration")
check("tailscale: the panel-host login-URL check is a fullmatch, not a prefix test",
      'startswith("https://login.tailscale.com/")' not in _tsi_src
      and "TS_LOGIN_URL_RE.fullmatch" in _tsi_src)
check("tailscale: both flows share ONE definition of the URL",
      _sm_hosts._TS_LOGIN_URL_RE is _privmod.TS_LOGIN_URL_RE)
_ts_good = "https://login.tailscale.com/a/0123456789abcdef"
check("tailscale: a real login URL is accepted",
      _privmod.TS_LOGIN_URL_RE.fullmatch(_ts_good) is not None)
for _ts_bad in (_ts_good + '"><img src=x>',            # the prefix test accepted this
                _ts_good + " and more",
                _ts_good + "?next=https://evil.example",
                "https://login.tailscale.com.evil.example/x",
                "https://login.tailscale.com/"):        # the path is required, not optional
    check("tailscale: %r is refused" % _ts_bad[:46],
          _privmod.TS_LOGIN_URL_RE.fullmatch(_ts_bad) is None)

# ── The peer check may not hand `ping` an option ──────────────────────────────────────────────
# `host` went straight from the request into ["ping", "-c", "1", "-W", "3", host]. There is no
# shell, so this is option injection rather than command injection — but argv[-1] starting with a
# dash is read by ping as a flag, and "the argument cannot be an option" is the rule
# privileged.USERNAME_RE and models._SHELL_IDENT_RE already apply for exactly this reason.
for _ph in ("100.64.1.2", "host.example.ts.net", "[fd7a:115c::1]", "192.168.1.10", "a-b.example"):
    check("peer host: %r accepted" % _ph, _tsi.valid_peer_host(_ph))
for _ph in ("-f", "--help", "-I eth0", "", "   ", "a;reboot", "$(id)", "a b", "x" * 300):
    check("peer host: %r refused" % _ph, not _tsi.valid_peer_host(_ph))
check("peer check: an invalid host is refused before ping runs, not pinged",
      _tsi.check_peer_reachability("-f") == {"reachable": False, "latency_ms": 0})

# ── _da() escapes the values it puts in a single-quoted attribute ─────────────────────────────
# _da builds `data-args='<json>'` for the delegated dispatcher. It escaped ' -> &#39; but left &
# alone, so a value containing the TEXT "&#39;" was decoded by the HTML parser into a real quote,
# closing the attribute early and turning the rest into further attributes on the tag. Reachable
# through a remote's name (SAFE_LABEL_RE blocks < > " ' ` \ but not &) -> REMOTE_NAME ->
# rebootNagRender. The CSP blocks the payload that would make it an XSS; the escaping is still wrong.
_panel_js = open(os.path.join(_root, "static", "js", "panel.js"), encoding="utf-8").read()
_da_src = _panel_js[_panel_js.index("window._da = function"):]
_da_src = _da_src[:_da_src.index("\n};")]
_da_amp, _da_quote = _da_src.find("replace(/&/g, '&amp;')"), _da_src.find("replace(/'/g")
check("_da: ampersands are escaped in data-args", _da_amp >= 0)
# .find, not .index: a missing escape is the thing being tested for, and raising here would take
# the whole suite down with a ValueError instead of reporting one FAIL.
check("_da: ...before the single quotes, or & would re-escape the & of &#39;",
      _da_amp >= 0 and _da_quote >= 0 and _da_amp < _da_quote,
      "amp at %d, quote at %d" % (_da_amp, _da_quote))

# ── The uninstaller removes everything the installer put OUTSIDE the panel directory ──────────
# install.sh writes in five places beyond PANEL_DIR. uninstall.sh removed two of them, so a host
# that had "removed the panel" kept a root-owned helper tree, a weekly root cron still running
# `npm install -g` every Sunday, and a host-wide vm.swappiness change — while the script's own
# header and the README both described the removal as complete.
_uninst = open(os.path.join(_root, "uninstall.sh"), encoding="utf-8").read()
# Mentioning a path is not removing it — the `if [ -f <path> ]` guard mentions it too. Collect the
# paths that actually appear as an argument to rm, so deleting the `rm` and keeping the guard (a
# very easy edit to make by accident) reads as the regression it is.
#
# The systemd unit is rm'd through "${UNIT_FILE}", which uninstall.sh sets from its own SYSTEM_UNIT
# literal — resolve that one variable rather than special-casing the two paths it stands for.
_sys_unit = re.search(r'SYSTEM_UNIT="([^"]+)"', _uninst)
_uninst_rm = set()
for _line in _uninst.splitlines():
    _cmd = _line.strip()
    # A removal may be prefixed with the sudo-when-not-root variable: the pieces install.sh writes
    # via `sudo` on a PER-USER install need the same to come back off, so those lines read
    # `${U_SUDO} rm -rf …`. Strip a leading variable expansion before the prefix test, or every
    # one of them reads as "not a removal" — which is how this gate first responded to the fix.
    _cmd = re.sub(r"^if\s+", "", _cmd)
    _cmd = re.sub(r"^\$\{[A-Za-z_][A-Za-z0-9_]*\}\s+", "", _cmd)
    _cmd = re.sub(r";\s*then\s*$", "", _cmd)
    if not _cmd.startswith("rm "):
        continue
    if _sys_unit:
        _cmd = _cmd.replace('"${UNIT_FILE}"', _sys_unit.group(1)).replace(
            '"${UNIT_FILE}.d"', _sys_unit.group(1) + ".d")
    _uninst_rm |= set(re.findall(r"/(?:etc|usr/local)/[A-Za-z0-9._/${}-]+", _cmd))


def _is_removed(path):
    """True when uninstall.sh rm's `path`, or a directory containing it."""
    return any(path == r or path.startswith(r.rstrip("/") + "/") for r in _uninst_rm)


for _path, _why in (
        ("/usr/local/lib/linuxgsm-panel", "the root-owned helper, db_maintenance, panel.conf and installer"),
        ("/etc/cron.d/lgsm-node-tools", "the weekly npm/gamedig root cron"),
        ("/etc/sysctl.d/99-linuxgsm-panel.conf", "the host-wide sysctl tuning"),
        ("/etc/sudoers.d/linuxgsm-panel", "the sudoers grant"),
        ("/usr/local/bin/linuxgsm-panel-recover", "the recovery command")):
    check("uninstall.sh rm's %s (%s)" % (_path, _why), _is_removed(_path),
          "rm targets: %s" % sorted(_uninst_rm))
check("uninstall.sh removes the systemd priority drop-in too", '"${UNIT_FILE}.d"' in _uninst)
# ...and the list above is derived, not remembered: whatever install.sh writes under /etc or
# /usr/local, the uninstaller has to rm. This is what makes the NEXT one impossible to forget.
_inst_src = open(os.path.join(_root, "install.sh"), encoding="utf-8").read()
_inst_paths = set(re.findall(r"/(?:etc|usr/local)/[A-Za-z0-9._/-]*linuxgsm[A-Za-z0-9._/-]*",
                             _inst_src))
_inst_paths |= set(re.findall(r"/etc/cron\.d/[A-Za-z0-9._-]+", _inst_src))
_inst_paths = {_p.rstrip("/") for _p in _inst_paths if _p.count("/") > 2}
_unremoved = sorted(_p for _p in _inst_paths if not _is_removed(_p))
# The scan above proves a path is rm'd SOMEWHERE in the file. It has no model of the `if
# [ "${MODE}" = "system" ]` guard, so for a long time it passed while three of those removals were
# unreachable on a per-user install — install.sh calls ensure_gamedig() and install_root_tools()
# unconditionally, before its own root/user split, and both use sudo when not root. So the paths
# that a user-mode install CREATES must be rm'd outside that branch.
# rindex, not index: uninstall.sh tests MODE earlier too (to print the service user in the
# summary), and splitting on the first occurrence puts the whole cleanup block on the wrong side
# — which is how this check first reported a fix that was already in place.
_uninst_cut = _uninst.rindex('if [ "${MODE}" = "system" ]; then')
_uninst_sys = _uninst[_uninst_cut:]
_uninst_common = _uninst[:_uninst_cut]
_user_created = ["/usr/local/lib/linuxgsm-panel", "/etc/cron.d/lgsm-node-tools",
                 "/usr/local/bin/linuxgsm-panel-recover"]


def _rm_targets(text):
    """The paths this chunk of script actually passes to `rm` — MENTIONING one is not removing it.
    The `if [ -f <path> ]` guard names it too, and a first version of this check was satisfied by
    that guard alone: the removal moved back into the system-only branch and it still passed."""
    out = set()
    for _l in text.splitlines():
        _c = re.sub(r"^if\s+", "", _l.strip())
        _c = re.sub(r"^\$\{[A-Za-z_][A-Za-z0-9_]*\}\s+", "", _c)
        _c = re.sub(r";\s*then\s*$", "", _c)
        if _c.startswith("rm "):
            out |= set(re.findall(r"/(?:etc|usr/local)/[A-Za-z0-9._/${}-]+", _c))
    return out


_common_rm = _rm_targets(_uninst_common)
_only_system = [p for p in _user_created if p not in _common_rm]
check("uninstall.sh: what a PER-USER install creates is removed outside the system-only branch",
      not _only_system, "system-mode only: %s" % _only_system)

check("uninstall.sh accounts for every panel path install.sh writes outside PANEL_DIR",
      not _unremoved, "not removed: %s" % _unremoved)

# ── Dead CSS must not out-specify live CSS ────────────────────────────────────────────
# A "STAT CARDS" block held .stat-card / .stat-value / .empty-state* — used by no template and no
# script — and a SECOND .stat-label. Equal specificity, later in the file, so the dead rule beat the
# live .stat-label under "LIVE STAT TILES" and every stat tile rendered at .75rem/--text-muted
# instead of the .66rem/#8b98a5 that rule asks for. Unused rules are only harmless when they do not
# collide, which is why this checks the collision and not just the disuse.
_css_raw = open(os.path.join(_root, "static", "css", "panel.css"), encoding="utf-8").read()
_css = re.sub(r"/\*.*?\*/", "", _css_raw, flags=re.S)      # comments describe rules; they are not rules


def _toplevel_class_rules(css):
    """Single-class selectors declared at the TOP level, i.e. outside any @media block.

    Media-query overrides re-declare .btn, .card-body and friends on purpose, so counting those as
    duplicates would flag the whole responsive section. Depth tracking is what separates the two."""
    out, depth, i = [], 0, 0
    while i < len(css):
        c = css[i]
        if c == "{":
            if depth == 0:
                head = css[:i].rsplit("}", 1)[-1].rsplit("{", 1)[-1].strip()
                m = re.fullmatch(r"(\.[A-Za-z][\w-]*)", head)
                if m:
                    out.append(m.group(1))
            depth += 1
        elif c == "}":
            depth = max(0, depth - 1)
        i += 1
    return out


# ── The console's timestamp gutter must not make its line taller ──────────────────────────────
# `.console-ts` is an inline-block with `overflow: hidden`, and per CSS an inline-block whose
# overflow is not `visible` takes its baseline from its BOTTOM MARGIN EDGE instead of from its last
# line box. It therefore hangs below the text beside it and the line box grows by a descender to
# fit: measured at 24.44px per stamped line against 18.72px for an unstamped one, which reads as
# ragged double-spacing wherever the two meet. Reported as "why is there like a extra space
# inbetween lines".
#
# `vertical-align` takes the gutter out of baseline alignment and the effect goes, rendering
# identically. This pins the PAIR, because either declaration alone is harmless and it is only
# together that they misbehave — so a later tidy that drops the vertical-align brings it back.
_cts = re.search(r"\.console-ts\s*\{([^}]*)\}", _css)
check("panel.css: the console timestamp gutter rule was found", _cts is not None,
      "no .console-ts rule — the check below would prove nothing")
_cts_body = _cts.group(1) if _cts else ""
check("panel.css: a clipped inline-block gutter also sets vertical-align, or it grows the line",
      not (re.search(r"overflow\s*:\s*(hidden|auto|scroll)", _cts_body)
           and "inline-block" in _cts_body)
      or re.search(r"vertical-align\s*:", _cts_body),
      "overflow on an inline-block moves its baseline to the bottom margin edge; without "
      "vertical-align every stamped console line is ~6px taller than an unstamped one")

_css_rules = _toplevel_class_rules(_css)
_dupe_rules = sorted({r for r in _css_rules if _css_rules.count(r) > 1})
check("panel.css: no single-class rule is declared twice at the top level",
      not _dupe_rules, "declared twice: %s" % _dupe_rules)
# The gate above only means something if it can see a duplicate at all — prove it counts the rules
# it is meant to (.stat-label is the one that was doubled, and is still there exactly once).
check("panel.css: ...and the scan really reads the file's rules",
      _css_rules.count(".stat-label") == 1 and len(_css_rules) > 60,
      "found %d top-level class rules" % len(_css_rules))
# ...and the dead selectors themselves are gone, with nothing in the UI asking for them.
_markup = "".join(open(_p, encoding="utf-8").read()
                  for _p in sorted(glob.glob(os.path.join(_root, "templates", "*.html")))
                  + sorted(glob.glob(os.path.join(_root, "static", "js", "*.js"))))
# Comments talk ABOUT class names ("shows an empty-state when nothing matches") without using them,
# so strip them first or the prose answers for the markup.
_markup = re.sub(r"<!--.*?-->|\{#.*?#\}|/\*.*?\*/", "", _markup, flags=re.S)
_markup = re.sub(r"^\s*//.*$", "", _markup, flags=re.M)
for _dead in ("stat-card", "stat-value", "empty-state"):
    check("panel.css: .%s is gone" % _dead,
          not re.search(r"\.%s[\w-]*\s*\{" % _dead, _css))
    check("...and nothing in the UI asks for .%s" % _dead, _dead not in _markup)


# ── A harness must not delete the developer's last database copy ──────────────────────────────
# Each of these refuses to run while data/panel.db EXISTS, and then cleans up after itself by
# unlinking what it created. panel.db.backup was not in the "already there, leave it alone" set,
# so it was unlinked every run — and it is not scratch: models._ensure_db_healthy keeps it as the
# rolling KNOWN-GOOD copy and restores from it when the live database is corrupt.
#
# The window is narrow and it is precisely the wrong one: the only state in which these run AND
# the backup exists is "panel.db is gone and this copy is the last one left".
import ast as _pe_ast
_PE_HARNESSES = ["tests/perf_budget_test.py", "tests/manage_test.py",
                 "tests/setup_wizard_test.py", "tests/input_validation_test.py",
                 "tools/perf_bench.py"]
_pe_bad, _pe_seen = [], 0
for _f in _PE_HARNESSES:
    _src = open(os.path.join(_root, _f), encoding="utf-8").read()
    _tree = _pe_ast.parse(_src)
    # The names the cleanup unlinks, and the names it treats as pre-existing.
    _pre = None
    for _n in _pe_ast.walk(_tree):
        if (isinstance(_n, _pe_ast.Assign) and len(_n.targets) == 1
                and getattr(_n.targets[0], "id", "") == "_PREEXISTING"):
            _pre = _pe_ast.get_source_segment(_src, _n.value) or ""
    if _pre is None:
        _pe_bad.append("%s has no _PREEXISTING at all" % _f)
        continue
    _pe_seen += 1
    for _guarded in ("panel.db.backup", "panel.db-wal", "panel.db-shm"):
        if _guarded in _src and _guarded not in _pre:
            _pe_bad.append("%s unlinks %s but does not protect a pre-existing one" % (_f, _guarded))
check("harnesses: none deletes a pre-existing panel.db.backup / WAL / SHM",
      not _pe_bad, "; ".join(_pe_bad[:4]))
check("harnesses: ...and the scan actually read all of them", _pe_seen == len(_PE_HARNESSES),
      "only inspected %d of %d" % (_pe_seen, len(_PE_HARNESSES)))

# ── recover.sh must not be pointed at another user's "panel" ──────────────────────────────────
# It runs as root during a lockout and scans /home/*/.config/systemd/user/ for a unit, reading
# WorkingDirectory out of it. /home/* is one directory PER LOCAL USER, and the panel creates a
# Linux account per game server (useradd -m), so those homes exist by design — anyone with code
# execution as a game server can plant a unit there. The scan took the FIRST match and broke, and
# glob order is alphabetical, so "aaaserver" beat "ubuntu" and `sudo linuxgsm-panel-recover` ran
# their manage.py and was handed the new superadmin password the operator was typing.
#
# Driven by RUNNING the real script against a sandbox /home (PANEL_RECOVER_HOMES), not by grepping
# it — the property is which install it picks, and only running it can answer that.
import subprocess as _rv_sub
import tempfile as _rv_tmp

_rv_root = _rv_tmp.mkdtemp(prefix="recover-homes-")


def _rv_plant(user, dirname):
    """A per-user install: a unit naming `dirname`, and a manage.py in it."""
    _unit_dir = os.path.join(_rv_root, user, ".config", "systemd", "user")
    os.makedirs(_unit_dir, exist_ok=True)
    _panel = os.path.join(_rv_root, user, dirname)
    os.makedirs(_panel, exist_ok=True)
    open(os.path.join(_panel, "manage.py"), "w").close()
    with open(os.path.join(_unit_dir, "linuxgsm-panel.service"), "w", encoding="utf-8") as _fh:
        _fh.write("WorkingDirectory=%s\n" % _panel)
    return _panel


def _rv_run():
    """recover.sh with the scan pointed at the sandbox. HOME is set somewhere empty so the
    per-user branch above the scan cannot match, and list-users keeps it read-only."""
    return _rv_sub.run(["bash", os.path.join(_root, "recover.sh"), "list-users"],
                       capture_output=True, text=True, timeout=60,
                       env={**os.environ, "PANEL_RECOVER_HOMES": _rv_root,
                            "HOME": os.path.join(_rv_root, "_nohome")})


_rv_real = _rv_plant("ubuntu", "linuxgsm-panel")
_rv_evil = _rv_plant("aaaserver", "evil")
_rv_two = _rv_run()
check("recover.sh: two candidate installs is a refusal, not a silent pick",
      _rv_two.returncode == 1 and "Refusing to guess" in _rv_two.stderr,
      "rc=%d err=%r" % (_rv_two.returncode, _rv_two.stderr[-200:]))
check("recover.sh: ...and it never chose the alphabetically-first one",
      _rv_evil not in (_rv_two.stdout + _rv_two.stderr).split("Using ")[-1].split("\n")[0],
      "it announced %r" % (_rv_two.stderr[-200:],))
check("recover.sh: the refusal NAMES both, so the operator can tell them apart",
      _rv_real in _rv_two.stderr and _rv_evil in _rv_two.stderr,
      _rv_two.stderr[-300:])

# Positive control: ONE candidate is still found and used without complaint — otherwise this gate
# passes just as well against a script that refuses everything and helps nobody.
_shutil.rmtree(os.path.join(_rv_root, "aaaserver"))
_rv_one = _rv_run()
check("recover.sh: a single install is still located (positive control)",
      "Refusing to guess" not in _rv_one.stderr and _rv_real in _rv_one.stderr,
      "rc=%d err=%r" % (_rv_one.returncode, _rv_one.stderr[-200:]))
check("recover.sh: ...and it says which install it is driving, before any password is typed",
      ("Using %s" % _rv_real) in _rv_one.stderr, _rv_one.stderr[-200:])
_shutil.rmtree(_rv_root, ignore_errors=True)

# ── Every part file must actually be RUN ──────────────────────────────────────────────────────
# The suite is now a runner plus tests/unit/part*.py, and the runner names the parts explicitly.
# Drop one from that list — or add a part and forget to — and the suite reports a smaller total
# and still exits 0. That is the same silent pass as a suite that SKIPs, and it is the failure this
# file exists to catch, so the shape of the file is not allowed to have it.
import pathlib as _upl
_upart_files = sorted(q.name[:-3] for q in _upl.Path(_UNIT_ROOT, "tests", "unit").glob("part*.py"))
_urunner = open(os.path.join(_UNIT_ROOT, "tests", "unit_test.py"), encoding="utf-8").read()
_umissing = [p for p in _upart_files if p not in _urunner]
check("unit suite: every tests/unit/part*.py is imported by the runner",
      not _umissing, "never run: %s" % _umissing)
check("unit suite: the runner imports at least as many parts as exist",
      len(_upart_files) >= 6, "found %d part files" % len(_upart_files))

# ── every _run() command is a literal, or shlex.quote()d ─────────────────────────────────────
# _run() executes with shell=True. Bandit rates that HIGH (B602) and the repo suppresses it,
# correctly: every one of its call sites today passes either a string literal or a value wrapped
# in shlex.quote(). But that is a property held by CONVENTION, and the suppression means nothing
# will complain the day someone writes _run(f"systemctl restart {name}") with `name` off a form.
# The suppression is only honest if something enforces what it assumes.
#
# A part is accepted when it is:
#   * a literal, or an f-string/%-format built only from literals;
#   * shlex.quote(...);
#   * a local name provably bound to a literal in the same function — including a `for x in [...]`
#     over constants. That is what makes `tee = "tee" if root else "sudo tee"` and
#     `log_file = "/var/log/apt/history.log"` pass without a marker, since they are genuinely safe.
# Anything else fails, and the fix is shlex.quote() — not an exemption.
import ast as _sh_ast

_SHELL_RUNNERS = {"_run"}


def _literal_names(fn):
    """Names bound ONLY to string literals inside `fn` — assignments, and loops over literal lists.
    A name rebound to anything non-literal anywhere in the function is excluded, so a variable that
    is a constant on one branch and a request value on another is never treated as safe."""
    good, bad = set(), set()

    def _is_lit(node):
        if isinstance(node, _sh_ast.Constant):
            return isinstance(node.value, str)
        if isinstance(node, _sh_ast.IfExp):          # "tee" if root else "sudo tee"
            return _is_lit(node.body) and _is_lit(node.orelse)
        if isinstance(node, _sh_ast.JoinedStr):
            return all(not isinstance(v, _sh_ast.FormattedValue) for v in node.values)
        return False

    for n in _sh_ast.walk(fn):
        if isinstance(n, _sh_ast.Assign):
            for t in n.targets:
                if isinstance(t, _sh_ast.Name):
                    (good if _is_lit(n.value) else bad).add(t.id)
        elif isinstance(n, _sh_ast.For) and isinstance(n.target, _sh_ast.Name):
            seq = n.iter
            if (isinstance(seq, (_sh_ast.List, _sh_ast.Tuple))
                    and all(_is_lit(e) for e in seq.elts)):
                good.add(n.target.id)
            else:
                bad.add(n.target.id)
    return good - bad


def _shell_part_ok(node, lits):
    if isinstance(node, _sh_ast.Constant):
        return True
    if isinstance(node, _sh_ast.Name):
        return node.id in lits
    if isinstance(node, _sh_ast.IfExp):
        return _shell_part_ok(node.body, lits) and _shell_part_ok(node.orelse, lits)
    if isinstance(node, _sh_ast.Call):
        f = node.func
        if (isinstance(f, _sh_ast.Attribute) and f.attr == "quote") or \
                (isinstance(f, _sh_ast.Name) and f.id == "quote"):
            return True                                     # shlex.quote(x)
        # remote_command() is the one other accepted builder. It is safe by a different mechanism:
        # check_args() validates every argument against the verb's own full-match validator, and
        # the body is shlex.join() except for the _REMOTE_ACTIONS verbs that build their own
        # string. That is not taken on trust — the injection sweep below drives every verb and
        # argument position with shell metacharacters and fails if one reaches the interpreted
        # part of the command. The two gates interlock: this exemption is only as good as that
        # sweep, and that sweep is what would break first.
        return (isinstance(f, _sh_ast.Attribute) and f.attr == "remote_command")
    if isinstance(node, _sh_ast.JoinedStr):                 # f"..."
        return all(_shell_part_ok(v.value, lits) if isinstance(v, _sh_ast.FormattedValue) else True
                   for v in node.values)
    if isinstance(node, _sh_ast.BinOp):                     # "a" + x, "a %s" % (x,)
        if isinstance(node.op, _sh_ast.Mod):
            rhs = node.right
            elts = rhs.elts if isinstance(rhs, (_sh_ast.Tuple, _sh_ast.List)) else [rhs]
            return _shell_part_ok(node.left, lits) and all(_shell_part_ok(e, lits) for e in elts)
        return _shell_part_ok(node.left, lits) and _shell_part_ok(node.right, lits)
    return False


_shell_bad, _shell_seen = [], 0
for _py in sorted(glob.glob(os.path.join(_root, "panel", "**", "*.py"), recursive=True)
                  + [os.path.join(_root, "app.py")]):
    try:
        _tree = _sh_ast.parse(open(_py, encoding="utf-8").read())
    except SyntaxError:
        continue
    for _fn in _sh_ast.walk(_tree):
        if not isinstance(_fn, (_sh_ast.FunctionDef, _sh_ast.AsyncFunctionDef)):
            continue
        _lits = _literal_names(_fn)
        for _c in _sh_ast.walk(_fn):
            if (isinstance(_c, _sh_ast.Call) and isinstance(_c.func, _sh_ast.Name)
                    and _c.func.id in _SHELL_RUNNERS and _c.args):
                _shell_seen += 1
                if not _shell_part_ok(_c.args[0], _lits):
                    _shell_bad.append("%s:%d in %s()" % (os.path.basename(_py), _c.lineno, _fn.name))
# The positive control for the gate below: an AST walk that matches nothing passes it vacuously.
# The floor tracks the real count and moves with it — it went 30 -> 29 when
# enable_unattended_upgrades stopped hand-rolling `printf … | sudo tee` and went through the write
# verb like every other root-owned write in that module.
check("shell: the _run() scan actually found the call sites", _shell_seen >= 29,
      "only %d matched — the scan stopped finding them, so the gate below proves nothing"
      % _shell_seen)
check("shell: every _run() command is a literal or shlex.quote()d", not _shell_bad,
      "unquoted interpolation into a shell=True command at: " + "; ".join(_shell_bad[:5]))

# ── no remote verb can put a shell metacharacter where the shell will read it ─────────────────
# remote_command() renders a verb as a shell string that runs AS ROOT on a remote host. Most of it
# is shlex.join(), which quotes everything. But _REMOTE_ACTIONS verbs build their own string, and
# four of them interpolate their arguments UNQUOTED — f2b-set-sshd-ports into a sed program,
# sshd-set-directive into another, content-scan into a for-list, content-dir-create into install
# -o/-g.
#
# Those are safe today, and only because their validators are strict full-matches over charsets
# with no metacharacters in them. Nothing tested that. Loosening one — letting a directive value
# take a space, adding '+' to a port list — would open command injection as root over SSH, and
# every existing test would still pass.
#
# So this asserts the property the quoting-free style depends on, for EVERY verb in the table
# including ones added later: feed each argument position a payload of shell metacharacters, and
# either the validator rejects it, or it must not survive anywhere the shell would act on it.
# Two prefixes, and the digit one is not padding: a validator that demands a leading digit (a port
# list) rejects every "x..." payload before the metacharacter is ever considered, so the sweep
# passed over a real injection and only an unrelated older test caught it. A payload has to be
# plausible enough to reach the charset being tested.
_INJ_SEEDS = [";id", "$(id)", "`id`", "|id", "&&id", "\nid", ">out", "<in", "'y", '"y', " id",
              "*", "$IFS", "\\", "#c"]
# Single characters as well as seeded ones. A charset can be narrow enough to reject every payload
# with letters in it and still admit the one character that matters — a lone "'" ends the quoting
# around a sed program, and "1'y" was refused for the "y" while "1'" would have gone through. The
# quote characters belong here for exactly that reason.
_INJ_BARE = ";|&$`<>* '\"\\\n"
_INJ_PAYLOADS = ([("x" + _s) for _s in _INJ_SEEDS] + [("1" + _s) for _s in _INJ_SEEDS]
                 + [("1" + _c) for _c in _INJ_BARE] + [("x" + _c) for _c in _INJ_BARE])
_INJ_META = set(";|&$`\n<>*\\\"' #")


def _outside_single_quotes(cmd):
    """What the SHELL still interprets: the command with '...' literals removed.

    This is the right model rather than a substring search — shlex.quote() wraps its argument in
    single quotes, and inside those the shell interprets nothing at all. So a payload that shows up
    only inside a quoted run is harmless, and one that shows up outside is not."""
    out, i, n = [], 0, len(cmd)
    while i < n:
        if cmd[i] == "'":
            j = cmd.find("'", i + 1)
            if j < 0:
                out.append(cmd[i:])
                break
            i = j + 1
        else:
            out.append(cmd[i])
            i += 1
    return "".join(out)


# Candidate values to fill the positions NOT under test. Anything a validator accepts will do —
# the point is only to get past check_args so the position being probed is actually reached.
_INJ_FILLERS = ["abc", "1", "22", "root", "yes", "no", "prohibit-password", "-", "gmod",
                "gmodserver", "PermitRootLogin", "PasswordAuthentication", "1720000000", "2",
                "ssh-ed25519 AAAA", "0", "10", "2026-01-02", "2026-01-02 03:04:05"]
_inj_bad, _inj_checked, _inj_nofill, _inj_base_exposed = [], 0, [], {}
for _verb in sorted(_priv._REMOTE_ACTIONS):
    _spec = _priv._ARGV.get(_verb)
    if not _spec:
        continue
    _vals = _spec[0]
    _rest = _vals[-1] if _vals and isinstance(_vals[-1], _priv.Rest) else None
    _arity = (len(_vals) - 1 + max(1, _rest.minimum)) if _rest else len(_vals)
    # A VALID filler per position, derived from the position's own validator. A single generic
    # filler made this sweep vacuous for every multi-argument verb: "abc" fails _sshd_key at arg0,
    # so check_args rejected before arg1 was ever reached and the payload was never tested there.
    _fill = []
    for _v in (list(_vals[:-1]) + [_rest.check] * max(1, _rest.minimum)) if _rest else list(_vals):
        _got = None
        for _cand in _INJ_FILLERS:
            try:
                _v(_cand)
                _got = _cand
                break
            except Exception:
                continue
        _fill.append(_got)
    if any(f is None for f in _fill):
        _inj_nofill.append(_verb)
        continue
    # Per-position fillers are not always a valid VECTOR: sshd-set-directive additionally requires
    # the value to be one its key allows, so "PermitRootLogin abc" passes both validators and is
    # still refused. Re-pick positions until check_args accepts the whole thing.
    try:
        _priv.check_args(_verb, _fill)
    except Exception:
        for _i in range(len(_fill)):
            for _cand in _INJ_FILLERS:
                _try = list(_fill)
                _try[_i] = _cand
                try:
                    _priv.check_args(_verb, _try)
                    _fill = _try
                    break
                except Exception:
                    continue
            try:
                _priv.check_args(_verb, _fill)
                break
            except Exception:
                continue
    try:
        _priv.check_args(_verb, _fill)
        _inj_base_exposed[_verb] = _outside_single_quotes(_priv.remote_command(_verb, _fill))
    except Exception:
        _inj_nofill.append(_verb)
        continue
    for _pos in range(_arity):
        for _pay in _INJ_PAYLOADS:
            _args = list(_fill)
            _args[_pos] = _pay
            _inj_checked += 1
            try:
                _priv.check_args(_verb, _args)
            except Exception:
                continue          # rejected by the validator — the intended outcome
            try:
                _cmd = _priv.remote_command(_verb, _args)
            except Exception:
                continue
            # Compare against the SAME command built from benign arguments and report any
            # metacharacter the payload ADDED to the interpreted part. Asking whether the whole
            # payload survived verbatim was too weak: a validator that accepts ";" but strips the
            # letters after it still yields a command separator, and that check saw nothing
            # because "1;id" was not present as a string.
            _exposed = _outside_single_quotes(_cmd)
            _added = [c for c in sorted(_INJ_META)
                      if _exposed.count(c) > _inj_base_exposed[_verb].count(c)]
            if _added:
                _inj_bad.append("%s arg%d %r adds %r" % (_verb, _pos, _pay, "".join(_added)))
check("privileged: every remote verb got a valid filler, so every position was reached",
      not _inj_nofill,
      "no filler found for: %s — those verbs' later arguments were never probed"
      % ", ".join(_inj_nofill))
check("privileged: the injection sweep actually ran", _inj_checked >= 200,
      "only %d combinations tried — the sweep stopped covering the table" % _inj_checked)
check("privileged: no remote verb lets a metacharacter reach the shell",
      not _inj_bad,
      "accepted AND left unquoted: " + "; ".join(_inj_bad[:6]))
