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
    # Guarded: if run_privileged took the SHELL path instead, _argvs stays empty and
    # `all(... for a in [])` is True — the check that owns the sudo boundary's argv discipline
    # would pass while the boundary was gone. (Today an IndexError five lines down happens to
    # catch it; that is an accident, not a gate.)
    check("transport: the argv path was actually taken, so the next checks examine a call",
          len(_argvs) == len(_T_SAMPLE),
          "%d of %d calls captured — the argv checks would be vacuous" % (len(_argvs),
                                                                          len(_T_SAMPLE)))
    check("transport: with the helper installed, the local path invokes it with argv",
          _argvs and all(a[:3] == ["sudo", "-n", _priv.HELPER_PATH] for a in _argvs),
          str(_argvs[:1]))
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
    # The auto-block reconcile's read. A log answer that FILLS the transport ceiling was cut (the
    # transports keep the oldest bytes), and a partial tally undercounts recent offenders — whom the
    # reconcile then RELEASES. At the ceiling it must answer None ("unread"), which the reconcile
    # treats as "leave every block where it is".
    _ac_line = "2026-09-03 10:00:00 x [sshd] Found 203.0.113.5\n"
    _ac_full = _ac_line * (_sm_core._MAX_OUTPUT_BYTES // len(_ac_line) + 1)
    _sm_core.run_privileged = lambda *a, **k: (_ac_full[:_sm_core._MAX_OUTPUT_BYTES], "", 0)
    check("remote attempt counts: a log read cut at the output ceiling is unread, not a partial tally",
          _sm_hosts.remote_fail2ban_attempt_counts(object(), days=7) is None,
          "a cut read was tallied — the reconcile would release the offenders it undercounts")
    _sm_core.run_privileged = lambda *a, **k: (_RAW, "", 0)
    check("remote attempt counts: (control) an ordinary read is tallied in full",
          _sm_hosts.remote_fail2ban_attempt_counts(object(), days=7)
          == {"203.0.113.5": 2, "198.51.100.9": 1},
          repr(_sm_hosts.remote_fail2ban_attempt_counts(object(), days=7)))
    _sm_core.run_privileged = lambda *a, **k: ("", "SSH command timed out", -1)
    check("remote attempt counts: a failed read is unread too",
          _sm_hosts.remote_fail2ban_attempt_counts(object(), days=7) is None, "")
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
    # The verb reads `sshd -T` back after the write. Stand that in: this runs on a developer box
    # with no root and possibly no sshd, and the read-back gets its own checks below.
    _hh_eff = {"ClientAliveInterval": "300", "ClientAliveCountMax": "2",
               "PermitRootLogin": "prohibit-password"}
    _hh._sshd_effective_value = lambda key: _hh_eff.get(key)
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

    # ── the WRITE is not the measurement; sshd -T is ───────────────────────────────────────────
    # sshd_config(5): "for each keyword, the first obtained value will be used". Ubuntu 22.04/24.04
    # make `Include /etc/ssh/sshd_config.d/*.conf` the first directive of sshd_config, and cloud
    # images put PasswordAuthentication in 50-cloud-init.conf — so everything this verb wrote into
    # sshd_config lost, and the verb returned 0 because the WRITE had succeeded. Bootstrap logged
    # "Hardening SSH configuration" on a host whose password login was still open to the internet,
    # and then rate-limited port 22 as though that were the remaining exposure.
    _hh_eff["PasswordAuthentication"] = "yes"          # what the distro drop-in still wins with
    _rc_over = _hh.do_sshd_set_directive(["PasswordAuthentication", "no"], None)
    check("sshd hardening: a directive another file overrides is NOT reported as applied",
          _rc_over != 0, "rc=%s" % _rc_over)
    # Positive control: the verb must still succeed when the value really did take effect, or the
    # check above would pass with the whole write removed.
    _hh_eff["PasswordAuthentication"] = "no"
    _rc_ok = _hh.do_sshd_set_directive(["PasswordAuthentication", "no"], None)
    check("sshd hardening: ...and one that really did take effect still reports success",
          _rc_ok == 0, "rc=%s" % _rc_ok)
    # A failed read is not a fact either way: "could not check" must not read as either answer.
    _hh._sshd_effective_value = lambda key: None
    _rc_unread = _hh.do_sshd_set_directive(["PasswordAuthentication", "no"], None)
    check("sshd hardening: an unreadable sshd -T is neither 'applied' nor 'overridden'",
          _rc_unread not in (0, _rc_over), "rc=%s, overridden is %s" % (_rc_unread, _rc_over))
    _hh._sshd_effective_value = lambda key: _hh_eff.get(key)

    # ...and the hardening has to land where sshd obtains it FIRST — a 00- drop-in, ahead of the
    # distro's 50-cloud-init.conf. Later files lose, so a 99- name would not have fixed this.
    _hh.SSHD_HARDENING_DROPIN = os.path.join(_hdir, "sshd_config.d", "00-panel-hardening.conf")
    open(_hh.SSHD_CONFIG, "w").write(
        "Include /etc/ssh/sshd_config.d/*.conf\n#PasswordAuthentication yes\nPort 22\n")
    _hh.do_sshd_set_directive(["PasswordAuthentication", "no"], None)
    _hh_drop = (open(_hh.SSHD_HARDENING_DROPIN).read()
                if os.path.exists(_hh.SSHD_HARDENING_DROPIN) else "")
    check("sshd hardening: an Include-style sshd_config also gets the panel's own drop-in",
          "PasswordAuthentication no" in _hh_drop, repr(_hh_drop))
    check("sshd hardening: ...whose name sorts BEFORE the distro's 50-cloud-init.conf",
          os.path.basename(_hh.SSHD_HARDENING_DROPIN) < "50-cloud-init.conf",
          os.path.basename(_hh.SSHD_HARDENING_DROPIN))
    # Setting a second directive keeps the first: a read-modify-write, not an append that leaves
    # a dead duplicate line behind it.
    _hh_eff["PermitRootLogin"] = "no"
    _hh.do_sshd_set_directive(["PermitRootLogin", "no"], None)
    _hh_drop2 = open(_hh.SSHD_HARDENING_DROPIN).read()
    check("sshd hardening: a second directive joins the drop-in without dropping the first",
          "PermitRootLogin no" in _hh_drop2 and "PasswordAuthentication no" in _hh_drop2
          and _hh_drop2.count("PasswordAuthentication") == 1, repr(_hh_drop2))
    # The other direction: a host that does NOT Include sshd_config.d (Debian 11, the RHEL family)
    # must not be left an inert file that looks like hardening and is read by nothing.
    _hh.SSHD_HARDENING_DROPIN = os.path.join(_hdir, "sshd_config.d", "00-panel-unused.conf")
    open(_hh.SSHD_CONFIG, "w").write("#PasswordAuthentication yes\nPort 22\n")
    _hh.do_sshd_set_directive(["PasswordAuthentication", "no"], None)
    check("sshd hardening: a host with no Include gets no inert drop-in",
          not os.path.exists(_hh.SSHD_HARDENING_DROPIN),
          "wrote a drop-in into a directory sshd never reads")
    check("sshd hardening: ...and that host is still hardened in sshd_config itself",
          "PasswordAuthentication no" in open(_hh.SSHD_CONFIG).read())
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

    # ── a file it COULD NOT READ is not a file with nothing in it ─────────────────────────────
    # This was a bare `except OSError: continue`, so a permission error or a corrupt .gz
    # (gzip.BadGzipFile is an OSError) silently shrank the tally and still returned 0. Both
    # callers — system_ops.fail2ban_top_ips and hosts.remote_fail2ban_top_ips — answer None on a
    # non-zero rc precisely so an unreadable log cannot pass for a quiet one, and returning 0
    # defeated that guard from the inside. A vanished rotation stays benign: logrotate really does
    # remove files mid-read, and that one is a smaller TRUE answer.
    _corrupt = os.path.join(_logdir, "fail2ban.log.3.gz")
    with open(_corrupt, "wb") as _cf:
        _cf.write(b"this is not gzip data at all")
    _buf2 = _io_t.StringIO()
    _stdout_save = sys.stdout
    sys.stdout = _buf2
    try:
        _rc_corrupt = _hl.do_f2b_log_lines(["2026-09-02"], None)
    finally:
        sys.stdout = _stdout_save
    check("f2b log read: a CORRUPT rotation fails the verb instead of shrinking the tally",
          _rc_corrupt != 0, "rc=%r with output %r" % (_rc_corrupt, _buf2.getvalue()[:120]))
    os.remove(_corrupt)
    # ...and a rotation that vanishes mid-read is still the benign case it was written for.
    _vanished = os.path.join(_logdir, "fail2ban.log.4")
    open(_vanished, "w", encoding="utf-8").close()
    # `open` is a BUILTIN, not an attribute of the module — reading _hl.open raises. Assigning it
    # does work, because a module global shadows the builtin for code inside that module, so set it
    # from the real builtin and delete it again afterwards.
    _real_open = open

    def _open_but_gone(path, *a, **k):
        if path == _vanished:
            raise FileNotFoundError(2, "No such file or directory", path)
        return _real_open(path, *a, **k)

    _hl.open = _open_but_gone
    _buf3 = _io_t.StringIO()
    _stdout_save = sys.stdout
    sys.stdout = _buf3
    try:
        _rc_gone = _hl.do_f2b_log_lines(["2026-09-02"], None)
    finally:
        sys.stdout = _stdout_save
        del _hl.open          # restore the builtin lookup, don't leave a module global behind
    check("f2b log read: a rotation that VANISHED mid-read is still benign (rc 0)",
          _rc_gone == 0 and "Found 203.0.113.5" in _buf3.getvalue(),
          "rc=%r" % (_rc_gone,))
    os.remove(_vanished)
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
_CEILING = {"sudo=True": 3, "_sudo_sh": 0}   # measured at the time of writing; lower only

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
    # ...and the ceiling must be TIGHT. A `<=` bound cannot notice itself being raised — mutation
    # -testing this gate showed exactly that: changing 3 to 9 broke nothing, so the "never raise"
    # half was a comment, not a check. Requiring equality makes converting a site a two-line edit
    # (convert, then lower) and makes ADDING one an explicit, reviewed change to this number
    # rather than something that quietly fits under the slack.
    check("escalation census: the %s ceiling is tight — lower it when a site converts" % _kind,
          _limit == _census[_kind],
          "ceiling %d but %d site(s) found — set _CEILING[%r] = %d"
          % (_limit, _census[_kind], _kind, _census[_kind]))

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

# ── `sudo linuxgsm-panel-recover` must not execute a panel-writable file ─────────────────────
# The installer prints it as the lockout remedy and README documents it, so it runs as ROOT. It
# was a symlink to ${PANEL_DIR}/recover.sh — inside the checkout, which install.sh chowns to the
# panel user — so a compromised panel rewrote it and waited for the operator to reach for the
# documented recovery command. recover.sh does drop to the service user before touching the
# database, but that is line 112: everything above it is root, and an attacker replaces the whole
# file anyway.
_rec = open(os.path.join(_root, "install.sh"), encoding="utf-8").read()
check("install.sh: the recovery command is installed through one shared function",
      "install_recovery_command() {" in _rec and _rec.count("install_recovery_command") >= 4)
check("install.sh: ...which takes recover.sh from the COMMIT, not the working tree",
      "stage_root_source recover.sh recover.sh" in _rec)
check("install.sh: ...installs it root-owned beside the helper",
      '-o root -g root -m 0755 "${stage}" "${HELPER_DIR}/recover.sh"' in _rec)
# The point of the whole change: no call site may still symlink into the checkout directly.
check("install.sh: no symlink points /usr/local/bin at the checkout's recover.sh",
      'ln -sf "${PANEL_DIR}/recover.sh"' not in _rec,
      "a call site still links straight into PANEL_DIR")

# ── The sudoers grant itself ──────────────────────────────────────────────────────────────────
# The whole point of the verb table. install.sh writes a NARROW grant when every root-owned piece
# is in place, and the wide one otherwise — because a host that has the new code but has not had
# install.sh re-run as root still falls back to `sudo bash -c '<verb as text>'`, and narrowing
# under it would break every privileged action rather than secure anything.
_inst = open(os.path.join(_root, "install.sh"), encoding="utf-8").read()
check("install.sh: the narrow grant reaches ROOT only through the helper",
      'ALL=(root) NOPASSWD: ${HELPER_DST}' in _inst)
# The second line, and why it is not a widening: about 45 sites drive a game account with
# `sudo -u <user> bash -c ...` — the file browser, the GMod content mounts, the cron writers, the
# install flows — and under a helper-only grant every one of them failed. This grants those, and
# only those: a Runas GROUP, whose membership install.sh and the gameuser-group verb control.
check("install.sh: ...and grants becoming a GAME account, scoped to the group",
      'ALL=(%${GAME_GROUP}) NOPASSWD: ALL' in _inst)
check("install.sh: ...and that group is never root — the Runas list names no user directly",
      'NOPASSWD: ALL' not in _inst.replace('ALL=(%${GAME_GROUP}) NOPASSWD: ALL', '')
      .replace('ALL=(ALL) NOPASSWD:ALL', ''))
check("install.sh: the group is synced before the grant that names it is written",
      _inst.find("sync_game_user_group\n") < _inst.find('ALL=(%${GAME_GROUP})')
      and "sync_game_user_group()" in _inst)
# A person's account must never land in a grant that lets the panel become them. The rule is a
# property of the home directory — a LinuxGSM instance or a Steam content tree — not a uid range.
check("install.sh: only homes with a LinuxGSM/Steam tree join the group",
      '[ -d "${_gh}/lgsm/config-lgsm" ] || [ -d "${_gh}/serverfiles" ]' in _inst)
check("install.sh: the narrow grant is conditional on the root-owned pieces being installed",
      '[ "${HELPER_OK}" -eq 1 ] && [ "${ROOT_TOOLS_OK}" -eq 1 ]' in _inst)
check("install.sh: still validates whichever grant it wrote with visudo",
      "visudo -cf /etc/sudoers.d/linuxgsm-panel" in _inst)

# ── …and the grant must never be WIDENED by the side it constrains ───────────────────────────
# HELPER_OK was set from `[ -f "${PANEL_DIR}/tools/panel-helper" ]`, a path the panel user owns.
# `git update-index --skip-worktree` makes a deletion survive the update's `git reset --hard`, so
# the panel user could delete that file, leave it deleted, and have this function replace the
# narrow rule with NOPASSWD:ALL. The grant now also asks whether the helper is actually INSTALLED.
check("install.sh: a failed REFRESH cannot widen a grant that is already narrow",
      "|| root_tools_present" in _inst)
check("install.sh: root_tools_present reads the installed destinations, not the checkout",
      'for f in "${HELPER_DST:-}" "${DBM_DST:-}" "${INSTALLER_DST:-}" "${PANEL_CONF:-}"' in _inst
      and "PANEL_DIR" not in _inst[_inst.index("root_tools_present() {"):_inst.index("write_sudoers_grant() {")])
check("install.sh: and it requires each of them to be root-owned",
      'stat -c ' + chr(39) + '%U' + chr(39) + ' "${f}"' in _inst and '= "root"' in _inst)

# ── Root's copy of a boundary file comes from the object store, not the working tree ──────────
# `git reset --hard` does NOT guarantee the working tree matches the commit: --skip-worktree
# exempts a path from it, and a smudge filter in .git/info/attributes rewrites the file DURING
# checkout. Both live in .git/, which is panel-owned, and _gitc runs git AS THE CHECKOUT OWNER.
# `git cat-file blob` reads the committed bytes and consults neither.
check("install.sh: the root-owned pieces are staged with git cat-file, not copied from the tree",
      '_gitc cat-file blob "HEAD:${rel}"' in _inst)
check("install.sh: staging lands in the root-owned HELPER_DIR, not a panel-writable path",
      'local rel="$1" out="${HELPER_DIR}/.stage-$2"' in _inst)

# ...but the OBJECT STORE is panel-owned too, and git trusts it. A replace ref, or a loose object
# written under the committed blob's name, makes `cat-file blob HEAD:<path>` return the panel's
# bytes while HEAD still names the real upstream commit; and a checkout with no .git was copied
# as-is. As root on a checkout the panel user has a hand in, a boundary file must come from ROOT'S
# OWN clone of REPO_URL, at the panel's HEAD only once that clone shows it is upstream.
#
# Run the real functions against real repositories. `id -u` says 0, and the files are this test
# user's, so the checkout reads as the panel user's, which is exactly the update-path condition.
import subprocess as _rs_sub
import zlib as _rs_zlib
from shlex import quote as _rs_q


def _rs_git(*a, cwd=None, inp=None):
    return _rs_sub.run(["git", *a], cwd=cwd, input=inp, capture_output=True,
                       text=True).stdout.strip()


_rs_fns = (_inst[_inst.index("_gitc() {"):_inst.index("\n}\n", _inst.index("_gitc() {")) + 3]
           + _inst[_inst.index('ROOT_GIT="${HELPER_DIR}/.source.git"'):
                   _inst.index("\n}\n", _inst.index("stage_root_source() {")) + 3])
_rs_sb = _tempfile.mkdtemp(prefix="rootsrc-")
try:
    _rs_up = os.path.join(_rs_sb, "upstream")
    os.makedirs(os.path.join(_rs_up, "tools"))
    _rs_git("init", "-q", "-b", "main", _rs_up)
    for _k, _v in (("user.email", "t@example.invalid"), ("user.name", "t"),
                   ("commit.gpgsign", "false")):
        _rs_git("config", _k, _v, cwd=_rs_up)
    with open(os.path.join(_rs_up, "tools", "panel-helper"), "w") as _f:
        _f.write("GOOD-HELPER\n")
    _rs_git("add", "-A", cwd=_rs_up)
    _rs_git("commit", "-qm", "upstream", cwd=_rs_up)

    def _rs_case(name, tamper, roots=False, src=None, panel_user=None, script=None, seed=None):
        """Clone upstream as 'the panel's checkout', tamper with it, stage as 'root'."""
        d = os.path.join(_rs_sb, name)
        panel, helper = os.path.join(d, "panel"), os.path.join(d, "helper")
        os.makedirs(helper)
        if seed:
            seed(os.path.join(helper, ".source.git"))
        _rs_git("clone", "-q", "--no-hardlinks", _rs_up, panel)
        for _k, _v in (("user.email", "t@example.invalid"), ("user.name", "t"),
                       ("commit.gpgsign", "false")):
            _rs_git("config", _k, _v, cwd=panel)
        tamper(panel)
        # Only a BARE `id -u` is root: `id -u <panel user>` must still name that user.
        body = ("id() { [ \"$#\" -eq 1 ] && [ \"$1\" = -u ] && echo 0 || command id \"$@\"; }\n"
                "sudo() { [ \"$1\" = -u ] && shift 2; \"$@\"; }\n"
                "warn() { echo \"WARN $*\"; }\n"
                "H_SUDO=''\nPANEL_DIR=%s\nHELPER_DIR=%s\nREPO_URL=%s\nDEFAULT_BRANCH=main\n"
                % (_rs_q(panel), _rs_q(helper), _rs_q("file://" + _rs_up))
                + ("SRC=%s\nPANEL_USER=%s\nSCRIPT_PATH=%s\n"
                   % (_rs_q(src), _rs_q(panel_user),
                      _rs_q(script or os.path.join(src, "install.sh"))) if src else "")
                + _rs_fns
                + ("_checkout_is_roots() { return 0; }\n" if roots else "")
                + "_prepare_root_source\n"
                  "if s=\"$(stage_root_source tools/panel-helper panel-helper)\"; then\n"
                  "  echo \"STAGED=$(cat \"$s\")\"\nelse\n  echo STAGED-NOTHING\nfi\n")
        r = _rs_sub.run(["bash", "-c", body], capture_output=True, text=True)
        return r.stdout + r.stderr

    def _rs_replace_ref(panel):
        good = _rs_git("rev-parse", "HEAD:tools/panel-helper", cwd=panel)
        evil = _rs_git("hash-object", "-w", "--stdin", cwd=panel, inp="EVIL-HELPER\n")
        _rs_git("replace", "-f", good, evil, cwd=panel)

    def _rs_loose_shadow(panel):
        # Pack everything, then write a LOOSE object under the committed blob's name with other
        # content. git reads the loose one first and does not re-hash it.
        _rs_git("gc", "-q", "--prune=now", cwd=panel)
        good = _rs_git("rev-parse", "HEAD:tools/panel-helper", cwd=panel)
        payload = b"EVIL-HELPER\n"
        p = os.path.join(panel, ".git", "objects", good[:2], good[2:])
        os.makedirs(os.path.dirname(p), exist_ok=True)
        if os.path.exists(p):
            os.unlink(p)
        with open(p, "wb") as f:
            f.write(_rs_zlib.compress(b"blob %d\0" % len(payload) + payload))

    def _rs_no_git(panel):
        _shutil.rmtree(os.path.join(panel, ".git"))
        with open(os.path.join(panel, "tools", "panel-helper"), "w") as f:
            f.write("EVIL-HELPER\n")

    def _rs_local_commit(panel):
        with open(os.path.join(panel, "tools", "panel-helper"), "w") as f:
            f.write("LOCAL-HELPER\n")
        _rs_git("commit", "-qam", "local only", cwd=panel)

    # The attacks really do fool the panel's own git — otherwise the checks below prove nothing.
    _rs_probe = os.path.join(_rs_sb, "probe")
    _rs_git("clone", "-q", "--no-hardlinks", _rs_up, _rs_probe)
    _rs_replace_ref(_rs_probe)
    check("install.sh: (premise) a replace ref makes the panel's git return other bytes",
          _rs_git("cat-file", "blob", "HEAD:tools/panel-helper", cwd=_rs_probe) == "EVIL-HELPER")

    _rs_out = _rs_case("clean", lambda p: None)
    check("install.sh: root stages an untouched upstream checkout's helper (positive control)",
          "STAGED=GOOD-HELPER" in _rs_out, _rs_out[-300:])
    _rs_out = _rs_case("replace", _rs_replace_ref)
    check("install.sh: as root, a replace ref in the panel's .git does not reach the staged helper",
          "STAGED=GOOD-HELPER" in _rs_out and "EVIL" not in _rs_out, _rs_out[-300:])
    _rs_out = _rs_case("loose", _rs_loose_shadow)
    check("install.sh: ...nor does a loose object shadowing the committed blob",
          "STAGED=GOOD-HELPER" in _rs_out and "EVIL" not in _rs_out, _rs_out[-300:])
    _rs_out = _rs_case("nogit", _rs_no_git)
    check("install.sh: ...and deleting .git no longer makes root copy the tree",
          "STAGED-NOTHING" in _rs_out and "EVIL" not in _rs_out, _rs_out[-300:])
    # The refusal is cached and shared by every caller, so it must not name files it did not try:
    # a fresh install once asked it for recover.sh alone and was told the helper — placed seconds
    # earlier — "was NOT refreshed".
    check("install.sh: ...and the refusal does not claim the helper was left unrefreshed",
          "WARN" in _rs_out and "privileged helper" not in _rs_out, _rs_out[-300:])
    # Root's clone is kept between runs, and the panel's branch switcher changes which branch it
    # fetches. A ref left by an earlier branch whose name is a directory of the new one (`fix`, then
    # `fix/x`, or `main/x` then `main` as here) made git refuse the fetch on every later run, so
    # the helper was never refreshed again.
    def _rs_seed_branch_ref(git_dir):
        _rs_git("init", "-q", "--bare", git_dir)
        _rs_git("--git-dir", git_dir, "fetch", "-q", "--no-tags", "file://" + _rs_up,
                "+refs/heads/main:refs/remotes/origin/main/x")
    _rs_probe = os.path.join(_rs_sb, "dfprobe.git")
    _rs_seed_branch_ref(_rs_probe)
    check("install.sh: (premise) a ref under a branch-named directory blocks a fetch into it",
          _rs_sub.run(["git", "--git-dir", _rs_probe, "fetch", "-q", "--no-tags",
                       "file://" + _rs_up, "+refs/heads/main:refs/remotes/origin/main"],
                      capture_output=True).returncode != 0)
    _rs_out = _rs_case("branchref", lambda p: None, seed=_rs_seed_branch_ref)
    check("install.sh: a ref left in root's clone by an earlier branch does not block the fetch",
          "STAGED=GOOD-HELPER" in _rs_out and "Could not fetch" not in _rs_out, _rs_out[-300:])
    _rs_out = _rs_case("local", _rs_local_commit)
    check("install.sh: a HEAD that is not on upstream's branch is refused, and says so",
          "STAGED-NOTHING" in _rs_out and "LOCAL-HELPER" not in _rs_out
          and "not on file://" in _rs_out, _rs_out[-300:])
    # ...while a checkout that is ROOT'S OWN (a fresh install from an operator's clone, before the
    # chown) is still read directly, local commits and all.
    _rs_out = _rs_case("rootowned", _rs_local_commit, roots=True)
    check("install.sh: a checkout that is entirely root's is still staged from its own HEAD",
          "STAGED=LOCAL-HELPER" in _rs_out, _rs_out[-300:])

    # ...and a root UPDATE from the operator's own tree (`sudo bash install.sh` in a clone or an
    # unpacked tarball, SRC != PANEL_DIR) stages from THAT tree. Root's clone refused it — no .git,
    # a local or feature-branch commit, no network — so the panel code was updated while the
    # helper, db_maintenance and the installer stayed old, and a host still on the wide grant could
    # never be narrowed. fetch_code copies exactly that working tree into the checkout, and the
    # operator chose it as root, so refusing it protected nothing.
    #
    # "The panel user" is an account that owns none of it, except where the case says otherwise.
    import pwd as _rs_pwd
    _rs_me = _rs_pwd.getpwuid(os.getuid()).pw_name
    _rs_other = None
    for _n in ("nobody", "daemon", "bin"):
        try:
            if _n != _rs_me:
                _rs_pwd.getpwnam(_n)
                _rs_other = _n
                break
        except KeyError:
            continue
    check("install.sh: (premise) there is an account to play a panel user that owns nothing here",
          _rs_other is not None)

    def _rs_srctree(name, helper_text="SRC-HELPER\n", parent=None):
        t = os.path.join(parent or _rs_sb, name + "-src")
        os.makedirs(os.path.join(t, "tools"))
        for _fn in ("app.py", "install.sh"):
            open(os.path.join(t, _fn), "w").close()
        with open(os.path.join(t, "tools", "panel-helper"), "w") as f:
            f.write(helper_text)
        return t

    _rs_out = _rs_case("srctree", _rs_no_git, src=_rs_srctree("srctree"), panel_user=_rs_other)
    check("install.sh: a root update from the operator's tree stages the helper from that tree",
          "STAGED=SRC-HELPER" in _rs_out and "EVIL" not in _rs_out, _rs_out[-300:])
    # Refusals: the panel user must not be able to nominate the tree root reads. The tree counts
    # only while root is running ITS install.sh: the self-update verb runs the root-owned copy with
    # its working directory in the checkout, wherever the panel user makes that lead.
    _rs_out = _rs_case("srcself", _rs_no_git, src=_rs_srctree("srcself"), panel_user=_rs_other,
                       script=os.path.join(_rs_sb, "srcself", "helper", "install.sh"))
    check("install.sh: ...but not while the installer running is not that tree's own",
          "STAGED-NOTHING" in _rs_out and "SRC-HELPER" not in _rs_out, _rs_out[-300:])
    _rs_out = _rs_case("srcpanel", _rs_no_git, src=_rs_srctree("srcpanel"), panel_user=_rs_me)
    check("install.sh: ...but not from a tree the panel user owns",
          "STAGED-NOTHING" in _rs_out and "SRC-HELPER" not in _rs_out, _rs_out[-300:])
    _rs_t = _rs_srctree("srcworld")
    os.chmod(os.path.join(_rs_t, "tools"), 0o777)
    _rs_out = _rs_case("srcworld", _rs_no_git, src=_rs_t, panel_user=_rs_other)
    check("install.sh: ...nor through a directory anyone can write",
          "STAGED-NOTHING" in _rs_out and "SRC-HELPER" not in _rs_out, _rs_out[-300:])
    # ...nor from a tree in a directory the panel user could swap it out of.
    _rs_par = os.path.join(_rs_sb, "srcparent-dir")
    os.makedirs(_rs_par)
    os.chmod(_rs_par, 0o777)
    _rs_out = _rs_case("srcparent", _rs_no_git, src=_rs_srctree("srcparent", parent=_rs_par),
                       panel_user=_rs_other)
    check("install.sh: ...nor from a tree whose parent directory anyone can write",
          "STAGED-NOTHING" in _rs_out and "SRC-HELPER" not in _rs_out, _rs_out[-300:])
    # A tree the panel user owns cannot vouch for itself through links to root's own files: judged
    # after following links, `app.py -> /etc/passwd` resolved somewhere root-owned, and the
    # "helper" staged was /etc/passwd.
    check("install.sh: (premise) /etc/passwd is root's, in a root-owned directory",
          os.stat("/etc/passwd").st_uid == 0 and os.stat("/etc").st_uid == 0)
    _rs_t = _rs_srctree("srcvouch")
    for _rel in ("app.py", os.path.join("tools", "panel-helper")):
        os.unlink(os.path.join(_rs_t, _rel))
        os.symlink("/etc/passwd", os.path.join(_rs_t, _rel))
    _rs_out = _rs_case("srcvouch", _rs_no_git, src=_rs_t, panel_user=_rs_me)
    check("install.sh: ...nor from a panel-owned tree whose files link to root-owned ones",
          "STAGED-NOTHING" in _rs_out and "root:" not in _rs_out, _rs_out[-300:])
    # The checkout itself by another spelling (a symlinked home, or a link the panel user put in
    # place of ${PANEL_DIR}) is not the operator's tree, whoever owns it.
    _rs_t = os.path.join(_rs_sb, "srcsame-link")
    os.symlink(os.path.join(_rs_sb, "srcsame", "panel"), _rs_t)
    _rs_out = _rs_case("srcsame", _rs_no_git, src=_rs_t, panel_user=_rs_other)
    check("install.sh: ...nor from the checkout itself reached by another path",
          "STAGED-NOTHING" in _rs_out and "EVIL" not in _rs_out, _rs_out[-300:])
    # Positive control for that: SRC is resolved, so an operator's tree reached through a link is
    # still the operator's tree.
    _rs_t = os.path.join(_rs_sb, "srcvia-link")
    os.symlink(_rs_srctree("srcvia"), _rs_t)
    _rs_out = _rs_case("srcvia", _rs_no_git, src=_rs_t, panel_user=_rs_other)
    check("install.sh: an operator's tree reached through a link is still staged from",
          "STAGED=SRC-HELPER" in _rs_out, _rs_out[-300:])
    # No symlink on the way down to the file is followed: here one lands in a world-writable
    # directory.
    _rs_t = _rs_srctree("srclink")
    _rs_drop = os.path.join(_rs_sb, "drop")
    os.makedirs(_rs_drop)
    os.chmod(_rs_drop, 0o777)
    with open(os.path.join(_rs_drop, "helper"), "w") as _f:
        _f.write("DROPPED-HELPER\n")
    os.unlink(os.path.join(_rs_t, "tools", "panel-helper"))
    os.symlink(os.path.join(_rs_drop, "helper"), os.path.join(_rs_t, "tools", "panel-helper"))
    _rs_out = _rs_case("srclink", _rs_no_git, src=_rs_t, panel_user=_rs_other)
    check("install.sh: ...nor through a symlink that lands somewhere the panel user can write",
          "STAGED-NOTHING" in _rs_out and "DROPPED-HELPER" not in _rs_out, _rs_out[-300:])
finally:
    _shutil.rmtree(_rs_sb, ignore_errors=True)
for _src in ("HELPER_SRC", "DBM_SRC"):
    check("install.sh: no longer installs root-owned files straight from %s" % _src,
          _src not in _inst)

# The narrow grant must not quietly re-admit any of the things that were call sites. Each of these
# runs whatever argv you hand it, so permitting one is permitting everything.
# Sliced with find(), not index(): an anchor that has MOVED must fail this gate, not raise out of
# the module and take the other 1900 checks with it. (Injecting a change to the grant condition
# did exactly that — the suite died at import with a ValueError instead of reporting a failure.)
_g_i = _inst.find('if { [ "${HELPER_OK}"')
_g_j = _inst.find("chmod 440 /etc/sudoers.d")
check("install.sh: the sudoers grant block is where this gate expects it",
      _g_i != -1 and _g_j > _g_i, "start=%d end=%d" % (_g_i, _g_j))
_narrow = _inst[_g_i:_g_j] if (_g_i != -1 and _g_j > _g_i) else ""
# Scanned as the LINES THAT ARE WRITTEN, not as the whole block. The block's comments explain what
# the grant deliberately excludes, and naming `sudo -u` or `/bin/bash` in prose must not read as
# granting them — but the substring scan said it did. Extracting the echoed lines is also the
# stricter reading: with it, a widening cannot hide inside a comment either.
_g_else = _inst.find("\n    else\n", _g_i)
_narrow_branch = _inst[_g_i:_g_else] if (_g_i != -1 and _g_else > _g_i) else ""
_grant_lines = re.findall(r'echo "(\$\{PANEL_USER\}[^"]*)"', _narrow_branch)
check("install.sh: the gate found the narrow grant's own lines",
      len(_grant_lines) == 2, "found %r" % (_grant_lines,))
for _never in ("systemd-run", "/bin/bash", "/bin/sh", "tailscale", "sudo -u"):
    check("install.sh: the narrow grant does not permit %s" % _never,
          bool(_grant_lines) and not any(_never in _l for _l in _grant_lines),
          "grant=%r" % (_grant_lines,))
# ...and the Runas targets are exactly root (reachable only by running the helper) and the game
# group. An `ALL=(ALL)` here would be the wide grant wearing the narrow branch's name, and a named
# user would be a target whose membership nothing controls.
check("install.sh: the narrow grant's Runas targets are root-via-helper and the game group",
      sorted(re.findall(r"ALL=\((.*?)\)", " ".join(_grant_lines))) == ["%${GAME_GROUP}", "root"],
      "grant=%r" % (_grant_lines,))
check("install.sh: ...and root's line permits ONLY the helper, nothing else",
      any(_l.endswith("NOPASSWD: ${HELPER_DST}") for _l in _grant_lines if "(root)" in _l),
      "grant=%r" % (_grant_lines,))

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
          '"${_istage}" "${INSTALLER_DST}" 2>/dev/null && INST_OK=1' in _inst_txt)

# ── panel-self-update: root opens its log inside the panel's own data dir ──────────────────────
# _self_update_detached ran `open(os.path.join(data_dir, "self-update.log"), "w")` AS ROOT. data/
# belongs to the panel user, so a symlink at that name made root truncate — or create — any file
# on the box with one panel-self-update call. _open_log_in_dir pins the directory, unlinks the
# name and CREATES the log O_EXCL; a symlink and a hard link planted there must both survive
# untouched. Driven for real in a temp dir; the caller is then held to it by AST.
import ast as _sul_ast
_sul_tmp = _tempfile.mkdtemp(prefix="selfupdate-log-")
_sul_victim = os.path.join(_sul_tmp, "root-owned-file")
_sul_data = os.path.join(_sul_tmp, "data")
os.makedirs(_sul_data)
with open(_sul_victim, "w", encoding="utf-8") as _fh:
    _fh.write("ORIGINAL")
_sul_log = os.path.join(_sul_data, _helper.SELF_UPDATE_LOG)
os.symlink(_sul_victim, _sul_log)
with _helper._open_log_in_dir(_sul_data, _helper.SELF_UPDATE_LOG) as _fh:
    _fh.write("=== panel self-update ===\n")
check("helper self-update: a symlink at the log name is not written through",
      open(_sul_victim, encoding="utf-8").read() == "ORIGINAL",
      repr(open(_sul_victim, encoding="utf-8").read()))
check("helper self-update: ...and the log is a real file holding what was written (positive control)",
      not os.path.islink(_sul_log)
      and open(_sul_log, encoding="utf-8").read() == "=== panel self-update ===\n")
os.unlink(_sul_log)
os.link(_sul_victim, _sul_log)
with _helper._open_log_in_dir(_sul_data, _helper.SELF_UPDATE_LOG) as _fh:
    _fh.write("new run\n")
check("helper self-update: a HARD link at the log name is not truncated either",
      open(_sul_victim, encoding="utf-8").read() == "ORIGINAL",
      repr(open(_sul_victim, encoding="utf-8").read()))
check("helper self-update: ...the log is a fresh file owned like its directory",
      os.stat(_sul_log).st_nlink == 1 and os.stat(_sul_log).st_uid == os.stat(_sul_data).st_uid
      and open(_sul_log, encoding="utf-8").read() == "new run\n")
_sul_fn = next(n for n in _sul_ast.walk(_sul_ast.parse(open(_helper_path, encoding="utf-8").read()))
               if isinstance(n, _sul_ast.FunctionDef) and n.name == "_self_update_detached")
_sul_calls = [n.func.id for n in _sul_ast.walk(_sul_fn)
              if isinstance(n, _sul_ast.Call) and isinstance(n.func, _sul_ast.Name)]
check("helper self-update: the detached run opens its log through _open_log_in_dir, never open()",
      "_open_log_in_dir" in _sul_calls and "open" not in _sul_calls, repr(_sul_calls))

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

    # requirements.txt must pin the WHOLE closure, not just the direct dependencies. Pinning 12
    # packages left the rest floating. install.sh skips pip when the file is unchanged, and
    # `pip install -r` never upgrades a package that already satisfies a range, so a security fix
    # in Werkzeug or python-engineio never reached a host. Dependabot bumps only what is listed,
    # and pip-audit (now --no-deps) audits only what is listed. So: every listed package's own
    # requirements, for CPython 3.10-3.14 on Linux, must be listed too, at a version that
    # satisfies them. Read from the installed metadata, which must BE the pinned versions.
    import importlib.metadata as _rq_md
    try:
        from packaging.requirements import Requirement as _RqReq
        from packaging.utils import canonicalize_name as _rq_canon
    except ImportError:
        from pip._vendor.packaging.requirements import Requirement as _RqReq
        from pip._vendor.packaging.utils import canonicalize_name as _rq_canon

    def _rq_closure_gaps(text):
        pins, gaps = {}, []
        for ln in text.splitlines():
            ln = ln.split("#", 1)[0].strip()
            if not ln:
                continue
            req = _RqReq(ln)
            spec = [s for s in req.specifier if s.operator == "=="]
            if len(spec) != 1 or len(req.specifier) != 1:
                gaps.append("%s is not pinned with ==" % ln)
                continue
            pins[_rq_canon(req.name)] = spec[0].version
        envs = [{"python_version": "3.%d" % m, "python_full_version": "3.%d.0" % m,
                 "sys_platform": "linux", "platform_system": "Linux", "platform_machine": mach,
                 "implementation_name": "cpython", "platform_python_implementation": "CPython",
                 "os_name": "posix", "extra": ""}
                for m in (10, 11, 12, 13, 14) for mach in ("x86_64", "aarch64")]
        for name, ver in sorted(pins.items()):
            try:
                dist = _rq_md.distribution(name)
            except _rq_md.PackageNotFoundError:
                gaps.append("%s==%s is not installed here, so its requirements cannot be read"
                            % (name, ver))
                continue
            if dist.version != ver:
                gaps.append("%s is installed at %s but pinned at %s (pip install -r "
                            "requirements.txt)" % (name, dist.version, ver))
                continue
            for rd in dist.requires or []:
                sub = _RqReq(rd)
                if sub.marker is not None and not any(sub.marker.evaluate(e) for e in envs):
                    continue
                sub_name = _rq_canon(sub.name)
                if sub_name not in pins:
                    gaps.append("%s needs %s, which is not pinned" % (name, rd))
                elif not sub.specifier.contains(pins[sub_name], prereleases=True):
                    gaps.append("%s needs %s, but %s is pinned" % (name, rd, pins[sub_name]))
        return pins, gaps

    _rq_txt = open(os.path.join(_root, "requirements.txt"), encoding="utf-8").read()
    _rq_pins, _rq_gaps = _rq_closure_gaps(_rq_txt)
    check("requirements.txt: pins every package the panel's dependencies pull in",
          len(_rq_pins) > 12 and not _rq_gaps, "; ".join(_rq_gaps[:6]))
    # The gate catches a gap (so the pass above is not an empty list for want of looking): drop
    # one transitive pin and it must be named.
    _rq_cut = "\n".join(ln for ln in _rq_txt.splitlines() if not ln.startswith("werkzeug=="))
    _rq_cut_gaps = _rq_closure_gaps(_rq_cut)[1]
    check("requirements.txt: ...and the closure check names a dropped transitive pin (control)",
          any("werkzeug" in g for g in _rq_cut_gaps), repr(_rq_cut_gaps[:3]))
    _rq_sec = open(os.path.join(_root, ".github", "workflows", "security-code.yml"),
                   encoding="utf-8").read()
    check("security-code: pip-audit audits the pinned set itself, not a fresh resolution",
          re.search(r"^\s*- run: pip-audit --no-deps -r requirements\.txt\s*$", _rq_sec, re.M)
          is not None, "pip-audit resolves its own environment again")

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
    # ...and the flag has to actually gate EVERY root-owned step.
    #
    # Scoped to each function's own body. This used to be `_su_txt.index(<the guard>) >
    # _su_txt.index("install_root_tools() {")`, which asks only "does the first guard in the file
    # appear after this function starts" — so adding the same guard to an EARLIER function made it
    # read the wrong one and fail, and a guard deleted from install_root_tools while another
    # existed later would have passed. Take the function body and look in that.
    def _su_body(name):
        i = _su_txt.index(name + "() {")
        return _su_txt[i:_su_txt.index("\n}\n", i)]

    _su_guard = 'if [ "${ORIGIN_TRUSTED:-1}" -ne 1 ]; then'
    check("install.sh: install_root_tools returns early when the origin is not trusted",
          _su_guard in _su_body("install_root_tools"))
    check("install.sh: ...and the sudoers grant is not rewritten from an untrusted checkout",
          '[ "${ORIGIN_TRUSTED}" -eq 1 ] && write_sudoers_grant' in _su_txt)
    # install_recovery_command is the one root-owned file an untrusted origin could still place,
    # and it was NOT gated. On the update path fetch_code has already `git reset --hard`-ed to the
    # untrusted commit before check_origin_trusted runs, and this function stages recover.sh from
    # HEAD, installs it root:root 0755 and points `sudo linuxgsm-panel-recover` at it — the exact
    # lockout remedy the installer and README tell the operator to run, and which runs as root
    # until recover.sh:121. The gate lives inside the function because there are three call sites.
    check("install.sh: install_recovery_command returns early when the origin is not trusted",
          _su_guard in _su_body("install_recovery_command"))

    # ── the game-account enrolment guard must fail CLOSED ────────────────────────────────────
    # GAME_GROUP is a grant: the panel's sudoers line says it may BECOME any member, so enrolling
    # an account that can already run sudo turns the narrow grant into NOPASSWD:ALL with one extra
    # hop. The guard was `sudo -l -U <u> | grep -q "may run the following"` — so every answer that
    # is not that one English phrase read as "no sudo rights, safe to enrol". Run the real
    # function against each reply sudo can actually give.
    _cas = _su_between("can_already_sudo() {", "\n}\n")
    _cas_cases = [
        ("User x may run the following commands on h:", "yes",  "a sudo-capable account"),
        ("User x is not allowed to run sudo on h.",     "no",   "a plain game account"),
        ("sudo: unknown user x",                        "unknown", "sudo could not resolve it"),
        ("",                                            "unknown", "sudo missing or errored"),
        ("El usuario x puede ejecutar los siguientes comandos:",
                                                        "unknown", "a localized reply"),
    ]
    _cas_bad = []
    for _out, _want, _desc in _cas_cases:
        _r = _su_run(_cas + '\ncan_already_sudo x\n', "",
                     extra=("id() { echo 'x games'; }\n"
                            "sudo() { printf '%s' " + _su_shlex.quote(_out) + "; }\n"))
        _got = (_r.stdout or "").strip().splitlines()[-1:] or [""]
        if _got[0] != _want:
            _cas_bad.append("%s -> %r (want %s)" % (_desc, _got[0], _want))
    check("install.sh: the enrolment guard answers yes/no/unknown, and unknown for anything unclear",
          not _cas_bad, "; ".join(_cas_bad))
    # ...and the group half still short-circuits without asking sudo at all.
    _r = _su_run(_cas + '\ncan_already_sudo x\n', "",
                 extra=("id() { echo 'x sudo'; }\n"
                        "sudo() { echo 'SUDO WAS CALLED'; }\n"))
    check("install.sh: ...and a member of a privileged GROUP is 'yes' without consulting sudo",
          (_r.stdout or "").strip().endswith("yes") and "SUDO WAS CALLED" not in _r.stdout,
          repr(_r.stdout[:120]))
    # ...and "privileged" is not only sudo. docker/lxd/incus-admin/libvirt reach root through their
    # daemon, disk through the block device, staff through /usr/local; adm and shadow read logs and
    # hashes. None needs a sudoers entry, so `sudo -l -U` says "not allowed" and the account was
    # enrolled into the become-any-member grant. Every group privileged.py already refuses as
    # root-equivalent must be refused here too, with sudo answering the reassuring "no".
    _cas_rootish = sorted(set(_privmod._NEVER_A_CONTENT_GROUP) | {"incus-admin", "libvirt"})
    _cas_missed = []
    for _g in _cas_rootish:
        _r = _su_run(_cas + '\ncan_already_sudo x\n', "",
                     extra=("id() { echo 'x games %s'; }\n" % _g
                            + "sudo() { echo 'User x is not allowed to run sudo on h.'; }\n"))
        if not (_r.stdout or "").strip().endswith("yes"):
            _cas_missed.append("%s -> %r" % (_g, (_r.stdout or "").strip()[-20:]))
    check("install.sh: ...including docker, lxd, disk and the other root-equivalent groups",
          len(_cas_rootish) >= 12 and not _cas_missed, "; ".join(_cas_missed))
    _r = _su_run(_cas + '\ncan_already_sudo x\n', "",
                 extra=("id() { echo 'x games dockerish'; }\n"
                        "sudo() { echo 'User x is not allowed to run sudo on h.'; }\n"))
    check("install.sh: ...matched whole, so a lookalike group is still a plain 'no' (control)",
          (_r.stdout or "").strip().endswith("no"), repr(_r.stdout[-40:]))
    # The caller must act on all three: only `no` may enrol.
    _sync_body = _su_body("sync_game_user_group")
    check("install.sh: ...and only a definite 'no' enrols the account",
          "can_already_sudo" in _sync_body and "no)" in _sync_body
          and "usermod -aG" in _sync_body, _sync_body[:200])

    # ...and an account that gained sudo AFTER it was enrolled must have the grant TAKEN BACK.
    # The escalation test runs BEFORE the membership test and only ever `continue`d, and this
    # function runs on updates too — so an account enrolled while it had no sudo and since added to
    # `sudo` kept its GAME_GROUP membership on every later run while being told "Not enrolling" and
    # "The panel will not be able to manage that account's servers on this host". Both sentences
    # were false for it: the panel could still become it, and from there `sudo -i` reaches root.
    # Driven, not grepped: the loop is re-pointed at a sandbox /home and every mutating command is
    # a shim, so what is asserted is the argv that would have run.
    _sync_fn = _su_body("sync_game_user_group") + "\n}\n"
    _sync_home = _tempfile.mkdtemp(prefix="gamehome-")
    try:
        os.makedirs(os.path.join(_sync_home, "steam", "lgsm", "config-lgsm"))
        _sync_src = _sync_fn.replace("for _gh in /home/*;", "for _gh in %s/*;" % _sync_home)
        check("install.sh: (premise) the enrolment loop was found and re-pointed at a sandbox",
              ("%s/*" % _sync_home) in _sync_src and "/home/*" not in _sync_src,
              _sync_src[:200])
        _sync_mark = os.path.join(_sync_home, "calls.log")

        def _sync_run(groups, sudo_reply="User steam is not allowed to run sudo on h."):
            """Run the real loop over one sandbox account whose `id -nG` answers `groups`."""
            if os.path.exists(_sync_mark):
                os.remove(_sync_mark)
            # usermod/gpasswd are called with >/dev/null 2>&1, so the shims record to a file.
            _shim = ("ok() { echo \"OK $*\"; }\n"
                     "groupadd() { return 0; }\n"
                     "id() { [ \"${1:-}\" = -nG ] && { echo %s; return 0; }; return 0; }\n"
                     "sudo() { printf '%%s' %s; }\n"
                     "usermod() { echo \"USERMOD $*\" >> %s; return 0; }\n"
                     "gpasswd() { echo \"GPASSWD $*\" >> %s; return 0; }\n"
                     % (_su_shlex.quote(groups), _su_shlex.quote(sudo_reply),
                        _su_shlex.quote(_sync_mark), _su_shlex.quote(_sync_mark)))
            _rr = _su_run(_cas + "\n" + _sync_src + "\nsync_game_user_group\n",
                          "RUN_AS_ROOT=1\nGAME_GROUP=lgsmpanel-games\nPANEL_USER=lgsmpanel\n",
                          extra=_shim)
            _calls = (open(_sync_mark, encoding="utf-8").read()
                      if os.path.exists(_sync_mark) else "")
            return (_rr.stdout or "") + (_rr.stderr or ""), _calls

        _out, _calls = _sync_run("steam sudo lgsmpanel-games")
        check("install.sh: an enrolled account that GAINED sudo is removed from the game group",
              "GPASSWD -d steam lgsmpanel-games" in _calls,
              "the membership was left in place; calls=%r out=%r" % (_calls, _out[-200:]))
        check("install.sh: ...and is not told the panel merely declined to enrol it",
              "Not enrolling" not in _out and "Removed 'steam'" in _out,
              "two false sentences about a member the panel CAN still become: %r" % (_out[-300:],))
        _out, _calls = _sync_run("steam sudo")
        check("install.sh: ...while an account that was never a member just reads 'not enrolling'",
              "Not enrolling" in _out and "GPASSWD" not in _calls,
              "calls=%r out=%r" % (_calls, _out[-200:]))
        _out, _calls = _sync_run("steam")
        check("install.sh: ...and a plain game account is still enrolled (positive control)",
              "USERMOD -aG lgsmpanel-games steam" in _calls and "GPASSWD" not in _calls,
              "calls=%r out=%r" % (_calls, _out[-200:]))
    finally:
        _shutil.rmtree(_sync_home, ignore_errors=True)

    # ── "Port N is free for the panel" must not be printed when nothing was free ─────────────
    # choose_and_record_port probes 5000..5050 and left `port` at `desired` when the loop found
    # nothing — the value its own first iteration had just measured as BUSY. The caller compares
    # only against the input, so its two branches could say "a different port" or "it is free" and
    # nothing else: the one outcome where the service start, the health check and the firewall step
    # would ALL point at a dead port printed as the green tick, and the operator was sent to the
    # logs having been told the port was free.
    _port_block = _su_between('PANEL_PORT="$(choose_and_record_port', "\nfi\n")
    _port_shims = "die() { echo \"DIE $*\"; exit 7; }\nok() { echo \"OK $*\"; }\n"
    _port_env = "DESIRED_PORT=5000\nPANEL_DIR=/opt/panel\n"
    _r = _su_run(_port_block, _port_env,
                 extra=_port_shims + "choose_and_record_port() { printf ''; }\n")
    check("install.sh: a port probe that found nothing free stops the install",
          "DIE" in _r.stdout and "OK" not in _r.stdout, repr(_r.stdout[-220:]))
    check("install.sh: ...and says which range it searched",
          "5000-5050" in _r.stdout, repr(_r.stdout[-220:]))
    _r = _su_run(_port_block, _port_env,
                 extra=_port_shims + "choose_and_record_port() { echo 5000; }\n")
    check("install.sh: ...while a genuinely free desired port still reports free (positive control)",
          "OK Port 5000 is free for the panel" in _r.stdout, repr(_r.stdout[-220:]))
    _r = _su_run(_port_block, _port_env,
                 extra=_port_shims + "choose_and_record_port() { echo 5003; }\n")
    check("install.sh: ...and a fallback port is still reported as a fallback",
          "WARN Port 5000 is already in use" in _r.stdout and "5003" in _r.stdout,
          repr(_r.stdout[-220:]))
    # ...and the probe itself must not record a port it never found free.
    check("install.sh: the probe prints and records nothing when the range is exhausted",
          "if port is None:" in _su_txt and "raise SystemExit(0)" in _su_txt
          and _su_txt.index("if port is None:") < _su_txt.index('cfg["port"] = port'),
          "the exhausted case still falls through to the config write")

    # ...and it must not write THROUGH anything the panel user planted in data/. As root it used
    # `open(cfg + ".tmp", "w")`, os.replace and os.chmod on paths inside a panel-owned directory,
    # and all three follow a symlink, so root rewrote a file of the panel user's choosing. Run the
    # real function, as this user, against the two plants that used to work.
    _cp_fn = _su_between("choose_and_record_port() {", "\nPYEOF\n}\n")
    _cp_sb = _tempfile.mkdtemp(prefix="portpick-")
    try:
        def _cp_run(plant, extra=""):
            d = _tempfile.mkdtemp(dir=_cp_sb)
            os.makedirs(os.path.join(d, "panel", "data"))
            victim = os.path.join(d, "victim")
            with open(victim, "w") as f:
                f.write("VICTIM\n")
            if plant:
                os.symlink(victim, os.path.join(d, "panel", "data", plant))
            r = _su_run(_cp_fn + '\nchoose_and_record_port 47100\necho "RC=$?"\n',
                        "PANEL_DIR=%s\n" % _su_shlex.quote(os.path.join(d, "panel")), extra=extra)
            cfg = os.path.join(d, "panel", "data", "config.json")
            written = (open(cfg).read() if os.path.isfile(cfg) and not os.path.islink(cfg) else "")
            return r, open(victim).read(), written

        _r, _victim, _cfg = _cp_run(None)
        check("install.sh: the port picker records the port it chose (positive control)",
              '"port": 471' in _cfg and _victim == "VICTIM\n", repr((_r.stdout[-120:], _cfg)))
        _r, _victim, _cfg = _cp_run("config.json.tmp")
        check("install.sh: a symlink planted at the old temp name is not written through",
              _victim == "VICTIM\n" and '"port": 471' in _cfg,
              repr((_victim[:60], _r.stdout[-120:], _r.stderr[-160:])))
        _r, _victim, _cfg = _cp_run("config.json")
        check("install.sh: ...and a symlinked config.json is refused, not followed",
              _victim == "VICTIM\n" and "RC=3" in _r.stdout
              and "symbolic link" in _r.stderr, repr((_victim[:60], _r.stdout[-120:])))
        # As root it drops to whoever owns PANEL_DIR, so the kernel refuses what the script misses.
        _cp_sudo = ("id() { echo 0; }\n"
                    "sudo() { echo \"SUDO $*\" >&2; shift 2; \"$@\"; }\n")
        _r, _victim, _cfg = _cp_run(None, extra=_cp_sudo + "stat() { echo lgsmpanel; }\n")
        check("install.sh: as root over a panel-owned PANEL_DIR, the port is written as its owner",
              "SUDO -u lgsmpanel python3 -" in _r.stderr and '"port": 471' in _cfg,
              repr(_r.stderr[-200:]))
        _r, _victim, _cfg = _cp_run(None, extra=_cp_sudo + "stat() { echo root; }\n")
        check("install.sh: ...while a root-owned PANEL_DIR (the fresh install) stays root (control)",
              "SUDO" not in _r.stderr and '"port": 471' in _cfg, repr(_r.stderr[-200:]))
    finally:
        _shutil.rmtree(_cp_sb, ignore_errors=True)

    # ── the "already up to date" branch has to backfill EVERY root-owned piece ───────────────
    # That branch exists because root-owned state lives OUTSIDE the checkout and can be stale while
    # the code is current. /usr/local/bin/linuxgsm-panel-recover is exactly that, and it is what
    # this installer prints as THE lockout remedy — so the operator re-running the installer to
    # repair a lockout was the one person guaranteed to reach this branch, and got "Already up to
    # date", exit 0, and `command not found` on the very next line they were told to type.
    _uptodate = _su_between("# Nothing to FETCH is not nothing to DO.", "Already up to date")
    for _fn in ("check_origin_trusted", "install_root_tools", "write_sudoers_grant",
                "write_terminal_sudo_grant", "install_recovery_command"):
        check("install.sh: the 'already up to date' branch still runs %s" % _fn,
              _fn in _uptodate, _uptodate[-400:])

    # ── the firewall probe has to use the SUDO computed beside it ────────────────────────────
    # `ufw status` requires uid 0 — as an ordinary user it errors to stderr (discarded) and exits
    # non-zero. The three probes ran WITHOUT ${SUDO}, which is set fifteen lines above, so on the
    # documented non-root install every flag stayed 0: the auto-open never fired and the banner
    # printed the bare public URL with no caveat. The health check passes regardless, because it
    # probes 127.0.0.1 — so the install reported green while handing the user a blocked address.
    _ufw_probe = _su_between("# Firewall state.", "\nfi\n")
    _ufw_run = (_ufw_probe
                + '\necho "ACTIVE=${UFW_ACTIVE} TS=${TS_UFW} OPEN=${PORT_OPEN} READ=${UFW_READ}"\n')
    # A non-root run: ufw exists, and answers only when invoked through sudo.
    _r = _su_run(_ufw_run, 'PORT=5000\nSUDO="sudo"\n',
                 extra=("command() { [ \"$2\" = ufw ] && return 0; return 1; }\n"
                        "ufw() { echo 'ERROR: You need to be root to run this script' >&2; return 1; }\n"
                        "sudo() { [ \"$1\" = ufw ] && { echo 'Status: active'; "
                        "echo '5000/tcp                   ALLOW       Anywhere'; return 0; }; return 1; }\n"))
    check("install.sh: the firewall probe reads through sudo, so a non-root install sees the truth",
          "ACTIVE=1" in _r.stdout and "OPEN=1" in _r.stdout and "READ=1" in _r.stdout,
          repr(_r.stdout[-120:]))
    # ...and when ufw will not answer at all, that is UNKNOWN, not "inactive".
    _r = _su_run(_ufw_run, 'PORT=5000\nSUDO=""\n',
                 extra=("command() { [ \"$2\" = ufw ] && return 0; return 1; }\n"
                        "ufw() { echo 'ERROR: You need to be root to run this script' >&2; return 1; }\n"))
    check("install.sh: ...and a firewall that would not answer is unread, not reported inactive",
          "READ=0" in _r.stdout and "ACTIVE=0" in _r.stdout, repr(_r.stdout[-120:]))
    # ...and a real "inactive" answer IS a reading (positive control), so the two are distinct.
    _r = _su_run(_ufw_run, 'PORT=5000\nSUDO=""\n',
                 extra=("command() { [ \"$2\" = ufw ] && return 0; return 1; }\n"
                        "ufw() { echo 'Status: inactive'; }\n"))
    check("install.sh: ...while a genuine 'Status: inactive' counts as read",
          "READ=1" in _r.stdout and "ACTIVE=0" in _r.stdout, repr(_r.stdout[-120:]))
    # The banner must act on that distinction rather than printing a bare URL.
    check("install.sh: the URL banner says so when the firewall state is unknown",
          'UFW_READ}" -eq 0' in _su_txt and "firewall state unknown" in _su_txt)

    # ── uninstall.sh must not report work it did not do ──────────────────────────────────────
    _un_txt = open(os.path.join(_root, "uninstall.sh"), encoding="utf-8").read()

    def _un_fn(marker, end="\n}\n"):
        i = _un_txt.index(marker)
        return _un_txt[i:_un_txt.index(end, i)]

    # `systemctl --user` needs XDG_RUNTIME_DIR to reach the user bus. install.sh has defaulted it
    # since it was written, with a comment saying why; uninstall.sh never did — and every svc call
    # there ends in `|| true`, so a stop that never happened read exactly like one that did, and
    # the rm -rf a few lines later deleted the files out from under a running process.
    check("uninstall.sh: defaults XDG_RUNTIME_DIR, as install.sh does, so `systemctl --user` works",
          'XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"' in _un_txt)
    check("uninstall.sh: ...and refuses to delete the files of a service still running",
          "is-active linuxgsm-panel.service" in _un_txt
          and "Refusing to delete a running panel's files." in _un_txt)
    # Two success lines that were printed unconditionally beside a command ending in `|| true`.
    check("uninstall.sh: the UFW line reports what was actually removed",
          "_ufw_gone" in _un_txt and "No UFW rule for port" in _un_txt)
    # Searched FROM the userdel, not from the start of the file: `id "${PANEL_USER}"` also appears
    # in the guard above it ("only ever remove the dedicated panel service user"), so a plain
    # .index() finds that one and compares the wrong occurrence — the same trap a source-reading
    # gate in this file hit before.
    _un_del = _un_txt.index('userdel -r "${PANEL_USER}"')
    check("uninstall.sh: the panel-user line asks whether the account is really gone",
          'Could not remove the panel user' in _un_txt
          and _un_txt.find('id "${PANEL_USER}" >/dev/null 2>&1; then', _un_del) > _un_del)
    # ...and the residual warning names the credential, because that is what the operator thinks
    # they just deleted.
    check("uninstall.sh: ...and says the surviving user may still hold the remote SSH key",
          "SSH key used for remote hosts" in _un_txt)

    # ── what the panel writes OUTSIDE its own directory has to be removed with it ─────────────
    # privileged.py's WRITE_TARGETS is the authoritative list of root-owned files the panel puts
    # on the host. uninstall.sh did not mention fail2ban at all, so `rm -rf "${PANEL_DIR}"` took
    # data/auth.log and left an ENABLED jail whose logpath points at it.
    _wt_src = open(os.path.join(_root, "panel", "security", "privileged.py"),
                   encoding="utf-8").read()
    _f2b_all = sorted(set(re.findall(r'"(/etc/fail2ban/[^"]+)"', _wt_src)))
    # /etc/fail2ban/jail.local is deliberately NOT in this list, and the first version of this gate
    # demanded it — which would have had uninstall delete the OPERATOR's own fail2ban config, jails
    # for services that have nothing to do with the panel included. privileged.py says so on the
    # line above the constant: "fail2ban's operator-owned jail file". The panel writes INTO it; it
    # does not own it. Only the panel-NAMED files under jail.d/ and filter.d/ are the panel's to
    # remove, which is why this filters rather than taking WRITE_TARGETS whole.
    _f2b_owned = [t for t in _f2b_all
                  if ("linuxgsm-panel" in t or "zz-panel-whitelist" in t)]
    check("uninstall.sh: (premise) privileged.py writes panel-named fail2ban files",
          len(_f2b_owned) >= 3, repr(_f2b_owned))
    check("uninstall.sh: (premise) ...and jail.local is not one of them — it is the operator's",
          "/etc/fail2ban/jail.local" in _f2b_all
          and "/etc/fail2ban/jail.local" not in _f2b_owned, repr(_f2b_all))
    _f2b_missing = [t for t in _f2b_owned if t not in _un_txt]
    check("uninstall.sh: removes every fail2ban file the panel OWNS",
          not _f2b_missing, "not removed: %s" % _f2b_missing)
    check("uninstall.sh: ...and never deletes the operator's own jail.local",
          "/etc/fail2ban/jail.local" not in _un_txt)
    check("uninstall.sh: ...and reloads fail2ban so it stops watching the deleted log",
          "fail2ban-client reload" in _un_txt)

    # ── the host-SHARED pieces are only taken when they belong to this install ───────────────
    # /usr/local/lib/linuxgsm-panel, the node-tools cron and the recovery symlink are one set for
    # the whole host, and this block runs for an unprivileged uninstall too — so on a box with two
    # panels, removing the second took the first's helper and recovery command. panel.conf, inside
    # the directory being deleted, records which install owns them.
    def _su_between2(start, end):
        """_su_between, but over uninstall.sh — _su_txt is install.sh."""
        i = _un_txt.index(start)
        j = _un_txt.index(end, i)
        return _un_txt[i:j + len(end)]

    # Behavioural, not a presence check. The first version asserted that the code READ panel.conf
    # and mentioned SHARED_MINE — and a mutation that replaced the comparison with `if false`
    # passed it, because reading a file and then ignoring it looks identical from the outside.
    # To the end of the SHARED_MINE decision, not the first `fi` — that one closes the panel.conf
    # read, and slicing there left SHARED_MINE unset, which `set -u` turns into empty output.
    _shared_dec = _su_between2('SHARED_CONF="${SHARED_CONF:', "    SHARED_MINE=0\nfi\n")
    _shared_run = _shared_dec + '\necho "MINE=${SHARED_MINE}"\n'
    _shared_tmp = _tempfile.mkdtemp(prefix="sharedconf-")
    try:
        # The home scan below reads ${HOMES}, so every case here points it at a fixture rather than
        # at this machine's /home: a decision that depends on who happens to live on the box the
        # suite runs on is not a decision anything can gate.
        _homes = os.path.join(_shared_tmp, "home")

        def _home_with(*users):
            """A HOMES fixture where each named user has a per-user panel unit installed."""
            _shutil.rmtree(_homes, ignore_errors=True)
            for _u in users:
                os.makedirs(os.path.join(_homes, _u, ".config", "systemd", "user"))
                open(os.path.join(_homes, _u, ".config", "systemd", "user",
                                  "linuxgsm-panel.service"), "w").close()
            os.makedirs(_homes, exist_ok=True)
            return "PANEL_UNINSTALL_HOMES=%s\n" % _su_shlex.quote(_homes)

        _mine = os.path.join(_homes, "me", "linuxgsm-panel")
        _env_me = "PANEL_DIR=%s\n" % _su_shlex.quote(_mine)
        _sc = os.path.join(_shared_tmp, "panel.conf")
        with open(_sc, "w", encoding="utf-8") as _fh:
            _fh.write("panel_dir=/home/other/linuxgsm-panel\n")
        _r = _su_run(_shared_run, _env_me + "SHARED_CONF=%s\n" % _su_shlex.quote(_sc)
                     + _home_with())
        check("uninstall.sh: host-shared pieces are LEFT when panel.conf names another install",
              "MINE=0" in _r.stdout, repr(_r.stdout[-80:]))
        with open(_sc, "w", encoding="utf-8") as _fh:
            _fh.write("panel_dir=%s\n" % _mine)
        _r = _su_run(_shared_run, _env_me + "SHARED_CONF=%s\n" % _su_shlex.quote(_sc)
                     + _home_with("me"))
        check("uninstall.sh: ...and taken when it names this one (positive control)",
              "MINE=1" in _r.stdout, repr(_r.stdout[-80:]))
        # No panel.conf at all — an older install that never wrote one. Taking them is the old
        # behaviour and the right default; refusing would strand the leftovers this block exists for.
        _r = _su_run(_shared_run, _env_me + "SHARED_CONF=%s\n"
                     % _su_shlex.quote(os.path.join(_shared_tmp, "absent.conf"))
                     + _home_with("me"))
        check("uninstall.sh: ...and taken when no panel.conf records an owner",
              "MINE=1" in _r.stdout, repr(_r.stdout[-80:]))
        # ...and the case panel.conf CANNOT answer. install.sh rewrites it on every install and
        # every self-update, so it names whoever ran last, not whoever owns the shared tree: in the
        # ordinary ordering (alice installs, bob installs after her) it names BOB, and bob's
        # uninstall then read his own panel_dir back and took alice's helper, her recovery command
        # and the weekly cron while her panel was still running. The question has to be "is another
        # install still here?", which only a scan of the homes can answer.
        _r = _su_run(_shared_run, _env_me + "SHARED_CONF=%s\n" % _su_shlex.quote(_sc)
                     + _home_with("me", "alice"))
        check("uninstall.sh: host-shared pieces are LEFT while ANOTHER install is still on the host",
              "MINE=0" in _r.stdout,
              "panel.conf names this install, but alice's is still installed: %r"
              % _r.stdout[-120:])
        # ...and a home that is not an install does not count as one (a bare home, no unit file).
        _env_alice = _home_with("me")
        os.makedirs(os.path.join(_homes, "alice"))
        _r = _su_run(_shared_run, _env_me + "SHARED_CONF=%s\n" % _su_shlex.quote(_sc) + _env_alice)
        check("uninstall.sh: ...while a home with no panel unit is not another install (control)",
              "MINE=1" in _r.stdout, repr(_r.stdout[-120:]))

        # ── "is this home MINE?" is a question about identity, not about spelling ────────────
        # The exclusion compared ${HOMES}/* against ${PANEL_DIR} as TEXT. Those name the same
        # directory in different words on ordinary hosts — /home a symlink onto another
        # filesystem, a trailing slash on $HOME — and when they did, the only install on the box
        # matched ITSELF as OTHER_INSTALL. The decision is an OR, so panel.conf naming this
        # install could not override it: the root-owned helper tree, the weekly root
        # `npm install -g` cron and the dangling recovery symlink were all left behind, under a
        # warning naming an install that does not exist. That is the exact leftover this block
        # was added to remove.
        _env_sc_mine = "SHARED_CONF=%s\n" % _su_shlex.quote(_sc)
        with open(_sc, "w", encoding="utf-8") as _fh:
            _fh.write("panel_dir=%s\n" % _mine)
        _env_homes = _home_with("me")
        _homes_link = os.path.join(_shared_tmp, "homes-link")
        if os.path.islink(_homes_link):
            os.unlink(_homes_link)
        os.symlink(_homes, _homes_link)
        _r = _su_run(_shared_run,
                     "PANEL_DIR=%s\n" % _su_shlex.quote(
                         os.path.join(_homes_link, "me", "linuxgsm-panel"))
                     + _env_sc_mine + _env_homes)
        check("uninstall.sh: the only install on the host is not mistaken for another one",
              "MINE=1" in _r.stdout,
              "a symlinked home spells this install's own directory differently, and it is then "
              "read as a co-tenant: %r" % _r.stdout[-200:])
        _r = _su_run(_shared_run,
                     "PANEL_DIR=%s\n" % _su_shlex.quote(
                         os.path.join(_homes, "me") + "//linuxgsm-panel")
                     + _env_sc_mine + _env_homes)
        check("uninstall.sh: ...nor is it when $HOME carried a trailing slash",
              "MINE=1" in _r.stdout, repr(_r.stdout[-200:]))
        # ...and resolving paths did not turn the co-tenant case into a false negative: alice is
        # still another install when she is reached through the symlinked spelling too.
        _r = _su_run(_shared_run,
                     "PANEL_DIR=%s\n" % _su_shlex.quote(
                         os.path.join(_homes_link, "me", "linuxgsm-panel"))
                     + _env_sc_mine + _home_with("me", "alice"))
        check("uninstall.sh: ...while alice's install is still another install (control)",
              "MINE=0" in _r.stdout, repr(_r.stdout[-200:]))

        # ── the homes root this scans is a NAMESPACED knob ───────────────────────────────────
        # It was a bare `HOMES`, a name any shell may already carry for something else, and it
        # decides both whether the host-wide files are deleted and (through the case guard beside
        # the userdel) what a root `rm -rf` is allowed to touch. recover.sh namespaces the same
        # knob as PANEL_RECOVER_HOMES for exactly this reason. Both are exported here: only the
        # namespaced one may steer the scan.
        _other_homes = os.path.join(_shared_tmp, "inherited")
        os.makedirs(os.path.join(_other_homes, "alice", ".config", "systemd", "user"),
                    exist_ok=True)
        open(os.path.join(_other_homes, "alice", ".config", "systemd", "user",
                          "linuxgsm-panel.service"), "w").close()
        _r = _su_run(_shared_run, _env_me + _env_sc_mine + _home_with("me")
                     + "HOMES=%s\n" % _su_shlex.quote(_other_homes))
        check("uninstall.sh: an inherited bare $HOMES does not steer the home scan",
              "MINE=1" in _r.stdout,
              "a generic environment variable decided whether host-wide files are removed: %r"
              % _r.stdout[-200:])
        _r = _su_run(_shared_run, _env_me + _env_sc_mine
                     + "PANEL_UNINSTALL_HOMES=%s\n" % _su_shlex.quote(_other_homes))
        check("uninstall.sh: ...and the namespaced one does (positive control)",
              "MINE=0" in _r.stdout, repr(_r.stdout[-200:]))
    finally:
        _shutil.rmtree(_shared_tmp, ignore_errors=True)
    check("uninstall.sh: ...and says so when another install owns them",
          "belong to another install" in _un_txt)

    # ── the firewall rule the INSTALLER opened has to come off on the path it opened it ───────
    # The ufw removal lived inside `if [ "${MODE}" = "system" ]`, so a per-user uninstall never
    # closed the port — it printed "If you opened a firewall port for the panel…" instead, which
    # the operator did not: install.sh runs `${SUDO} ufw allow "${PORT}/tcp"` at column 0, after
    # its root/user split, so the installer opens it on the per-user path too. The port stayed
    # open on a host with no panel behind it.
    #
    # Run the region rather than reading it: "outside the MODE branch" is a property of where the
    # code sits, and the only honest way to ask is to run it as a per-user uninstall and see
    # whether ufw is called. The shims trace to a file because every call in here is redirected to
    # /dev/null — asserting on stdout would assert on nothing.
    # The slice starts at the U_SUDO computation, NOT at the firewall comment four lines below it.
    # Starting below it meant the test environment handed in `U_SUDO=sudo`, so nothing here asked
    # whether the code still computes it above the first command that needs it — and it has to:
    # move that assignment back down beside the /usr/local removals, as it was, and a per-user
    # uninstall dies on `set -u` at the ufw line. min() rather than a bare .index() so that a
    # version which DID move it fails this check by name instead of raising ValueError out of the
    # extraction and taking the rest of the file's checks with it.
    _usudo_i = _un_txt.index('U_SUDO=""')
    _fw_i = _un_txt.index("# ── Undo ONLY the panel's own firewall rule")
    check("uninstall.sh: ${U_SUDO} is computed above the first root-owned removal, not beside it",
          _usudo_i < _fw_i,
          "the ufw delete runs %d bytes BEFORE U_SUDO exists" % (_usudo_i - _fw_i))
    _fw_region = _un_txt[min(_usudo_i, _fw_i):
                         _un_txt.index("\n# ── Remove the panel files", _fw_i)]
    # Two places now have to be able to be the first sudo on the path, so the explanation is a
    # function with a once-guard rather than a line. Run it twice and count.
    _note_fn = _su_between2("_SUDO_NOTE_SHOWN=0", "\n}\n")
    _note_shim = 'info() { echo "INFO $*"; }\n'
    _r = _su_run(_note_fn + "\nsudo_note\nsudo_note\n", "U_SUDO=sudo\n", extra=_note_shim)
    check("uninstall.sh: the sudo explanation is printed once, not once per removal",
          _r.stdout.count("INFO ") == 1, repr(_r.stdout))
    _r = _su_run(_note_fn + "\nsudo_note\n", "U_SUDO=\n", extra=_note_shim)
    check("uninstall.sh: ...and not at all when there is no sudo to explain (control)",
          "INFO" not in _r.stdout, repr(_r.stdout))
    _fw_tmp = _tempfile.mkdtemp(prefix="uninst-fw-")
    try:
        _trace = os.path.join(_fw_tmp, "trace")
        # `id` is shimmed and U_SUDO is NOT supplied: the region derives it from the uid, which is
        # the thing under test. info() goes to the trace as well as to stdout because every
        # privileged call in here is redirected to /dev/null — the trace is the only stream where
        # the ORDER of "here is why I need sudo" against "sudo …" can be read back.
        _fw_shims = ('ok() { echo "OK $*"; }\n'
                     'id() { echo "${FAKE_UID}"; }\n'
                     'info() { echo "INFO $*"; echo "INFO $*" >> "${TRACE}"; }\n'
                     'ufw() { echo "UFW $*" >> "${TRACE}"; }\n'
                     'sudo() { echo "SUDO $*" >> "${TRACE}"; }\n'
                     'tailscale() { echo "TS $*" >> "${TRACE}"; }\n')

        def _fw_run(env):
            open(_trace, "w").close()
            _out = _su_run(_fw_region, "TRACE=%s\n" % _su_shlex.quote(_trace) + env,
                           extra=_fw_shims)
            return _out, open(_trace, encoding="utf-8").read()

        _r, _tr = _fw_run('MODE=user\nFAKE_UID=1000\nPANEL_PORT=5000\n'
                          'TS_DONE=0\nTS_CONF_UNREAD=0\nTS_MOUNT=/\n')
        check("uninstall.sh: a PER-USER uninstall closes the port its installer opened",
              "SUDO ufw delete allow 5000/tcp" in _tr,
              "nothing deleted the rule on the user path: %r / %r" % (_tr, _r.stdout[-120:]))
        check("uninstall.sh: ...and says so, rather than asking the operator to do it",
              "OK Removed the panel's UFW rule for port 5000" in _r.stdout,
              repr(_r.stdout[-160:]))
        check("uninstall.sh: ...and no longer blames the operator for a port they never opened",
              "If you opened a firewall port" not in _un_txt)

        # ── not knowing the port is not the same as there being no rule ────────────────────────
        # PANEL_PORT is blanked whenever data/config.json cannot be read or parsed, and the guard
        # below it is `[ -n "${PANEL_PORT}" ]` — so that case skipped the whole block in SILENCE,
        # leaving the rule the installer opened on a host with no panel behind it and saying
        # nothing. The Tailscale teardown two blocks down already hedges out loud about the very
        # same unreadable file. An empty read is not a measurement.
        # Own names: the sudo-ordering check below reads the _r/_tr from the run ABOVE, and
        # reusing them here made it assert against this run's trace instead. (It failed loudly
        # rather than passing wrongly, which is the only reason it was cheap to find.)
        _rnp, _trnp = _fw_run('MODE=user\nFAKE_UID=1000\nPANEL_PORT=\n'
                              'TS_DONE=0\nTS_CONF_UNREAD=0\nTS_MOUNT=/\n')
        check("uninstall.sh: a port it could not read is reported, not silently left open",
              "Could not read the panel's port" in _rnp.stdout,
              "said nothing about the rule it is leaving behind: %r" % (_rnp.stdout[-200:],))
        check("uninstall.sh: ...and it does not guess a port to delete instead",
              "ufw delete" not in _trnp,
              "deleted a rule for a port it never read: %r" % (_trnp,))

        # ── the account being ALREADY GONE must not end the uninstall ──────────────────────────
        # `PANEL_HOME="$(getent passwd ... | cut -d: -f6)"` runs under this file's own
        # `set -euo pipefail`. getent exits 2 when the account does not exist, pipefail carries
        # that out of the pipeline, and the assignment's status is the substitution's — so the
        # WHOLE uninstaller stopped there, printing nothing at all. Measured: exit 2, before the
        # next line. And a missing account is not an error here, it is the ordinary state when
        # someone re-runs this after a partial uninstall — precisely when they need it to work.
        #
        # The real line is lifted out of the file, not retyped, so a future edit is covered.
        _ge_m = re.findall(r'^\s*(PANEL_HOME="\$\(getent passwd[^\n]*)$', _un_txt, re.M)
        check("uninstall.sh: the service account's home is read by exactly one line",
              len(_ge_m) == 1, "found %d candidates: %r" % (len(_ge_m), _ge_m))
        if len(_ge_m) == 1:
            _ge = _sh_sub.run(
                ["bash", "-c", "set -euo pipefail\nPANEL_USER=no-such-account-for-a-test\n"
                               + _ge_m[0].strip() + "\nprintf 'REACHED:%s\\n' \"${PANEL_HOME}\""],
                capture_output=True, text=True)
            check("uninstall.sh: an account that is already gone does not abort the uninstall",
                  _ge.returncode == 0 and _ge.stdout.startswith("REACHED:"),
                  "rc=%d out=%r err=%r" % (_ge.returncode, _ge.stdout, _ge.stderr[-160:]))
            check("uninstall.sh: ...and reads back empty, so the default home path is used",
                  _ge.stdout.strip() == "REACHED:", repr(_ge.stdout))
            # Positive control: a real account still yields its real home, so the line was not
            # simply neutered into always answering nothing.
            _ge_ok = _sh_sub.run(
                ["bash", "-c", "set -euo pipefail\nPANEL_USER=root\n" + _ge_m[0].strip()
                               + "\nprintf 'REACHED:%s\\n' \"${PANEL_HOME}\""],
                capture_output=True, text=True)
            check("uninstall.sh: ...while an account that EXISTS still reports its home",
                  _ge_ok.returncode == 0 and _ge_ok.stdout.strip() not in ("REACHED:", ""),
                  "rc=%d out=%r" % (_ge_ok.returncode, _ge_ok.stdout))
        # ...and the operator is told WHY sudo is about to be asked for before it is asked for.
        # The explanation used to live beside the /usr/local removals further down, which stopped
        # being the first sudo on this path the moment the firewall rule moved out of the
        # system-only branch: a per-user uninstall reached a password prompt with nothing yet
        # printed to say what it was for. Both streams are in the trace, so this reads the order.
        # Both .index() calls are guarded. The `in` test short-circuits the first, but NOT the
        # second: with the note printed and no sudo reached — a real state on a host with nothing
        # left to remove — `_tr.index("SUDO ")` raised ValueError, and these parts are imported by
        # tests/unit_test.py at module scope, so that killed the ENTIRE unit suite at import
        # instead of failing this one check. A suite that dies reports nothing about the other
        # 2800 checks; an assertion must fail, not explode.
        _sudo_at = _tr.find("SUDO ")
        _note_at = _tr.find("INFO Some pieces live outside")
        check("uninstall.sh: a per-user uninstall says why it needs sudo BEFORE it asks",
              _note_at >= 0 and (_sudo_at < 0 or _note_at < _sudo_at),
              "sudo ran with no explanation printed first: %r" % _tr)
        # The root path still behaves exactly as it did (positive control), and a host with no
        # recorded port still touches nothing.
        _r, _tr = _fw_run('MODE=system\nFAKE_UID=0\nPANEL_PORT=5000\n'
                          'TS_DONE=0\nTS_CONF_UNREAD=0\nTS_MOUNT=/\n')
        check("uninstall.sh: ...while a root uninstall still deletes it directly (positive control)",
              "UFW delete allow 5000/tcp" in _tr, repr(_tr))
        check("uninstall.sh: ...and is not told it needs a sudo it does not need (control)",
              "INFO Some pieces live outside" not in _tr, repr(_tr))
        _r, _tr = _fw_run('MODE=user\nFAKE_UID=1000\nPANEL_PORT=\n'
                          'TS_DONE=0\nTS_CONF_UNREAD=0\nTS_MOUNT=/\n')
        check("uninstall.sh: ...and an install with no recorded port touches no firewall rule",
              "ufw" not in _tr.lower(), repr(_tr))

        # ── and the Tailscale teardown removes the panel's mapping, not the host's whole config ──
        # `tailscale serve reset` is "clear the entire serve/funnel config": it took every OTHER
        # mapping on the node with it — a /grafana mount, a funnel for a stats page — unlisted,
        # unlogged and unrecoverable, since serve config is not versioned. It then printed "it was
        # pointing at the panel", which nothing here had established.
        _r, _tr = _fw_run('MODE=system\nFAKE_UID=0\nPANEL_PORT=\n'
                          'TS_DONE=1\nTS_CONF_UNREAD=0\nTS_MOUNT=/lgsm-panel\n')
        check("uninstall.sh: the Tailscale teardown removes only the panel's own mount",
              "TS serve --bg --remove /lgsm-panel" in _tr and "reset" not in _tr,
              "this wipes every Serve/Funnel mapping on the host: %r" % _tr)
        check("uninstall.sh: ...and names the mount it removed",
              "at /lgsm-panel" in _r.stdout, repr(_r.stdout[-160:]))
        # ...and a panel that never set Serve up is still left alone (positive control).
        _r, _tr = _fw_run('MODE=system\nFAKE_UID=0\nPANEL_PORT=\n'
                          'TS_DONE=0\nTS_CONF_UNREAD=0\nTS_MOUNT=/lgsm-panel\n')
        check("uninstall.sh: ...and a host that never published the panel is untouched (control)",
              _tr == "", repr(_tr))

        # ── the Serve mapping a PER-USER panel published comes down too ──────────────────────
        # The teardown was gated on `[ "${MODE}" = "system" ]`, four lines below the block that
        # had just been moved OUT of that same gate for the same reason. Nothing about
        # tailscale_setup_done is system-only: the running panel writes it whenever
        # setup_tailscale_serve() succeeds (routes/tailscale.py, route_helpers.py), with no
        # install-mode split anywhere in that path. So a per-user panel left its Serve mapping
        # published on the tailnet, pointing at a backend that no longer exists.
        _r, _tr = _fw_run('MODE=user\nFAKE_UID=1000\nPANEL_PORT=\n'
                          'TS_DONE=1\nTS_CONF_UNREAD=0\nTS_MOUNT=/lgsm-panel\n')
        check("uninstall.sh: a PER-USER panel's Tailscale Serve mapping is removed too",
              "TS serve --bg --remove /lgsm-panel" in _tr,
              "the mapping stays on the tailnet pointing at a dead backend: %r" % _tr)

        # ── a mount that could not be read is never guessed at ───────────────────────────────
        # The config read used to substitute "/" for a value it could not validate — and "/" is a
        # real mount, the one most likely to belong to something ELSE on this node, so an
        # unreadable or malformed config.json ended in `tailscale serve --bg --remove /`. The
        # panel's own teardown refuses instead (disable_tailscale_serve() catches VerbError and
        # returns "That isn't a usable mount point." without calling the CLI). Empty is how that
        # reaches here, and nothing may be removed on it.
        _r, _tr = _fw_run('MODE=system\nFAKE_UID=0\nPANEL_PORT=\n'
                          'TS_DONE=1\nTS_CONF_UNREAD=1\nTS_MOUNT=\n')
        check("uninstall.sh: an unreadable mount removes NOTHING, least of all the root mount",
              "TS " not in _tr,
              "removed a mount this script had to guess at: %r" % _tr)
        check("uninstall.sh: ...and the operator is told where to look instead",
              "tailscale serve status" in _r.stdout
              and "Leaving this node's Tailscale Serve config alone" in _r.stdout,
              repr(_r.stdout[-320:]))
        # ...but a "/" the config genuinely RECORDS is still the panel's own mount, and still
        # comes off: config.py defaults tailscale_mount to "/", so refusing it wholesale would
        # strand the mapping of every panel that took the default (positive control).
        _r, _tr = _fw_run('MODE=system\nFAKE_UID=0\nPANEL_PORT=\n'
                          'TS_DONE=1\nTS_CONF_UNREAD=0\nTS_MOUNT=/\n')
        check("uninstall.sh: ...while a recorded \"/\" is the panel's own mount and is removed",
              "TS serve --bg --remove /\n" in _tr, repr(_tr))
    finally:
        _shutil.rmtree(_fw_tmp, ignore_errors=True)

    # ...and the mount it removes is the one the panel recorded, read before its config is deleted.
    _ts_read = (_su_between2('PANEL_PORT=""; TS_DONE=0', "\nfi\n")
                + '\necho "M=[${TS_MOUNT}] UNREAD=${TS_CONF_UNREAD}"\n')
    _ts_tmp = _tempfile.mkdtemp(prefix="uninst-ts-")
    try:
        os.makedirs(os.path.join(_ts_tmp, "data"))

        def _ts_mount_read(value, raw=None):
            """Read TS_MOUNT back out of a fixture config.json. `raw` writes the file verbatim."""
            with open(os.path.join(_ts_tmp, "data", "config.json"), "w", encoding="utf-8") as _fh:
                if raw is None:
                    json.dump({"port": 5000, "tailscale_mount": value}, _fh)
                else:
                    _fh.write(raw)
            return _su_run(_ts_read, "PANEL_DIR=%s\n" % _su_shlex.quote(_ts_tmp)).stdout

        check("uninstall.sh: the Tailscale mount comes from the panel's own config",
              "M=[/lgsm-panel]" in _ts_mount_read("/lgsm-panel"),
              repr(_ts_mount_read("/lgsm-panel")))
        check("uninstall.sh: ...defaulting to / for a panel that recorded nothing else (control)",
              "M=[/] UNREAD=0" in _ts_mount_read("/"), repr(_ts_mount_read("/")))
        # A mount beginning with "-" is an OPTION to `tailscale`, not a path, and this script runs
        # as root. Rejected the same way privileged.py's _ts_mount rejects it — and rejected means
        # EMPTY, not "/". Substituting "/" turned a value this script could not validate into the
        # removal of the mount most likely to belong to something else on the node; the panel's own
        # teardown answers the same input by refusing to call the CLI at all.
        check("uninstall.sh: ...and a mount that is not a mount point never reaches the CLI",
              "M=[] UNREAD=1" in _ts_mount_read("--set-path=/pwn"),
              repr(_ts_mount_read("--set-path=/pwn")))
        # ...and the same for a config.json that will not parse at all. The Serve flag is read out
        # of that same file by a `grep -q` on its TEXT, which still matches — so this case reached
        # the CLI too, with a mount nothing had read.
        check("uninstall.sh: ...nor does one read out of a config.json that will not parse",
              "M=[] UNREAD=1"
              in _ts_mount_read(None, raw='oops not json "tailscale_setup_done": true\n'),
              repr(_ts_mount_read(None, raw='oops not json "tailscale_setup_done": true\n')))
    finally:
        _shutil.rmtree(_ts_tmp, ignore_errors=True)

    # ── "Removed the dedicated panel user" must mean the SSH key went with it ────────────────
    # `rm -rf "${PANEL_DIR}"` only clears <home>/linuxgsm-panel. The key that authenticates to
    # every remote host this panel managed lives OUTSIDE it, at <home>/.ssh/id_rsa (ssh_manager's
    # default), and it is root-capable there — the remote grant is `sudo bash -c`. The teardown ran
    # `userdel -r … || userdel …`, and that fallback is userdel WITHOUT -r, which by definition
    # leaves the home; `userdel -r` itself exits 12 when it cannot remove the home, having already
    # deleted the account. Both cases asked only whether the ACCOUNT was gone, so the key survived
    # an uninstall that reported itself complete.
    _ud_block = _su_between2('    if [ "${PANEL_USER}" = "${SERVICE_USER}" ]', "        fi\n    fi\n")
    _ud_tmp = _tempfile.mkdtemp(prefix="uninst-user-")
    try:
        _ud_homes = os.path.join(_ud_tmp, "home")

        def _ud_run(userdel_body, home="lgsmpanel"):
            """Run the teardown against a fixture home, with the account state the shims decide."""
            _shutil.rmtree(_ud_homes, ignore_errors=True)
            _ph = os.path.join(_ud_homes, "lgsmpanel")
            os.makedirs(os.path.join(_ph, ".ssh"))
            with open(os.path.join(_ph, ".ssh", "id_rsa"), "w", encoding="utf-8") as _fh:
                _fh.write("PRIVATE KEY\n")
            # home="" stands for a passwd field that is the homes ROOT — the shape the rm -rf
            # guard has to refuse.
            _passwd_home = os.path.join(_ud_homes, home) if home else _ud_homes
            _shim = ('ok() { echo "OK $*"; }\n'
                     'loginctl() { :; }\n'
                     '_gone=0\n'
                     'getent() { echo "lgsmpanel:x:998:998::${PH}:/bin/bash"; }\n'
                     'id() { if [ "${_gone}" = 1 ]; then return 1; fi; return 0; }\n'
                     'userdel() { %s }\n' % userdel_body)
            _out = _su_run(_ud_block,
                           "PANEL_USER=lgsmpanel\nSERVICE_USER=lgsmpanel\n"
                           "HOMES=%s\nPH=%s\n" % (_su_shlex.quote(_ud_homes),
                                                  _su_shlex.quote(_passwd_home)),
                           extra=_shim)
            return _out, _ph

        # (a) userdel -r fails (rc 12 — "can't remove home directory"); the fallback deletes the
        #     account and leaves the home. This is the defect: the account is gone, so the old
        #     branch printed the success line over a surviving id_rsa.
        _r, _ph = _ud_run('if [ "${1:-}" = "-r" ]; then return 12; fi; _gone=1; return 0;')
        check("uninstall.sh: the panel user's home goes with the account, not just the account",
              not os.path.exists(os.path.join(_ph, ".ssh", "id_rsa")),
              "the SSH key that reaches every managed remote survived the uninstall: %r"
              % _r.stdout[-200:])
        check("uninstall.sh: ...and only then is the user reported as removed",
              "OK Removed the dedicated panel user" in _r.stdout, repr(_r.stdout[-200:]))
        # (b) userdel -r does its own job (positive control): nothing left to clean up, same line.
        _r, _ph = _ud_run('_gone=1; rm -rf "${PH}"; return 0;')
        check("uninstall.sh: ...and a userdel -r that worked still reports success (control)",
              "OK Removed the dedicated panel user" in _r.stdout and not os.path.isdir(_ph),
              repr(_r.stdout[-200:]))
        # (c) both attempts fail: the account is still live, so its home is NOT ours to delete —
        #     and the operator is told, rather than shown a success line.
        _r, _ph = _ud_run("return 1;")
        check("uninstall.sh: ...but a panel user that survived keeps its home (control)",
              os.path.exists(os.path.join(_ph, ".ssh", "id_rsa"))
              and "WARN Could not remove the panel user" in _r.stdout,
              repr(_r.stdout[-200:]))
        # (d) a home that is not a plain <homes>/<name> is never handed to rm -rf — here the homes
        #     root itself, which is what a passwd field of "/home" would resolve to. It is reported
        #     instead, because "left on disk" is the truth in that case too.
        _r, _ph = _ud_run('_gone=1; return 0;', home="")
        check("uninstall.sh: ...and a home outside <homes>/<name> is reported, never rm -rf'd",
              os.path.isdir(_ud_homes) and "WARN Removed the panel user" in _r.stdout,
              repr(_r.stdout[-200:]))
    finally:
        _shutil.rmtree(_ud_tmp, ignore_errors=True)

    # ── recover.sh must not pair a directory with another install's service user ─────────────
    _rec_txt = open(os.path.join(_root, "recover.sh"), encoding="utf-8").read()
    _rec_fallback = _rec_txt[_rec_txt.index('for d in "/home/lgsmpanel/linuxgsm-panel"'):]
    _rec_fallback = _rec_fallback[:_rec_fallback.index("done\n")]
    check("recover.sh: choosing a different panel dir clears the discarded install's service user",
          'SVC_USER=""' in _rec_fallback,
          "the stale user short-circuits the stat that derives it from the chosen directory")

    # ...and prove it by RUNNING the function both ways, rather than trusting the source text.
    _su_recov = _su_between("install_recovery_command() {", "\n}\n") + "\ninstall_recovery_command\n"
    _su_rshim = ("id() { echo 0; }\n"
                 "install() { echo \"INSTALL $*\"; }\n"
                 "ln() { echo \"LN $*\"; }\n"
                 "rm() { :; }\n"
                 "_prepare_root_source() { :; }\n"
                 "stage_root_source() { echo /tmp/staged-recover.sh; }\n")
    _r_untrusted = _su_run(_su_recov, "HELPER_DIR=/usr/local/lib/lgsmp\n"
                           + _su_env + "ORIGIN_TRUSTED=0\n", extra=_su_rshim)
    check("install.sh: an untrusted origin installs NO root-owned recover.sh",
          "INSTALL" not in _r_untrusted.stdout,
          repr(_r_untrusted.stdout[:200]))
    check("install.sh: ...and does not repoint the recovery symlink either",
          "LN" not in _r_untrusted.stdout, repr(_r_untrusted.stdout[:200]))
    check("install.sh: ...and says so, rather than failing silently",
          "WARN" in _r_untrusted.stdout, repr(_r_untrusted.stdout[:200]))
    # positive control: with a trusted origin it still does its job, so the checks above are
    # measuring the gate and not a function that no longer works.
    _r_trusted = _su_run(_su_recov, "HELPER_DIR=/usr/local/lib/lgsmp\n"
                         + _su_env + "ORIGIN_TRUSTED=1\n", extra=_su_rshim)
    check("install.sh: a trusted origin still installs the root-owned recover.sh",
          "INSTALL -o root -g root -m 0755" in _r_trusted.stdout
          and "LN -sf /usr/local/lib/lgsmp/recover.sh" in _r_trusted.stdout,
          repr(_r_trusted.stdout[:300]))

    # ...and when NO fresh copy can be staged, ROOT must still never aim the command into the
    # checkout. It fell back to `ln -sf ${PANEL_DIR}/recover.sh` whenever staging failed, and root's
    # own-clone staging refuses a tarball, a --src tree, a local commit and an offline host — all
    # legitimate root installs — so `sudo linuxgsm-panel-recover` ran a panel-writable file as root,
    # and on an update it REPOINTED a link that had been aimed at the root-owned copy.
    _su_ppanel = os.path.join(_su_sb, "panel")
    open(os.path.join(_su_ppanel, "recover.sh"), "w").close()
    _su_rlib = os.path.join(_su_sb, "rootlib")

    def _su_recfail(uid, helper_dir, owner="root", link_to="/elsewhere"):
        shim = ("id() { echo %s; }\n" % uid
                + "sudo() { \"$@\"; }\n"
                  "install() { echo \"INSTALL $*\"; }\n"
                  "ln() { echo \"LN $*\"; }\n"
                  "rm() { echo \"RM $*\"; }\n"
                  "stat() { echo %s; }\n" % owner
                + "readlink() { echo %s; }\n" % _su_shlex.quote(link_to)
                + "_prepare_root_source() { :; }\n"
                  "stage_root_source() { return 1; }\n")
        return _su_run(_su_recov, "HELPER_DIR=%s\n" % _su_shlex.quote(helper_dir)
                       + _su_env + "ORIGIN_TRUSTED=1\n", extra=shim).stdout

    _r = _su_recfail(0, "/usr/local/lib/lgsmp")
    check("install.sh: as root, a failed staging never links the recovery command into the checkout",
          "LN " not in _r and "WARN" in _r, repr(_r[:400]))
    _r = _su_recfail(0, "/usr/local/lib/lgsmp", link_to=os.path.join(_su_ppanel, "recover.sh"))
    check("install.sh: ...and unlinks one an older installer aimed at the checkout",
          "RM -f /usr/local/bin/linuxgsm-panel-recover" in _r and "LN " not in _r, repr(_r[:400]))
    _r = _su_recfail(0, "/usr/local/lib/lgsmp")
    check("install.sh: ...but leaves a link that points anywhere else alone (control)",
          "RM -f /usr/local/bin/linuxgsm-panel-recover" not in _r, repr(_r[:400]))
    open(os.path.join(_su_rlib, "recover.sh"), "w").close()
    _r = _su_recfail(0, _su_rlib)
    check("install.sh: ...it keeps a root-owned copy already in place (stale, but not panel-writable)",
          "LN -sf %s" % os.path.join(_su_rlib, "recover.sh") in _r
          and "LN -sf %s" % os.path.join(_su_ppanel, "recover.sh") not in _r, repr(_r[:400]))
    _r = _su_recfail(0, _su_rlib, owner="lgsmpanel")
    check("install.sh: ...but not one the panel user owns",
          "LN " not in _r, repr(_r[:400]))
    # Control: the ACCOUNT that owns the checkout (a per-user install) still gets the fallback —
    # it can rewrite what it runs anyway, and the gate above must not have removed that.
    _r = _su_recfail(1000, "/usr/local/lib/lgsmp")
    check("install.sh: a per-user run still falls back to the checkout's recover.sh (control)",
          "LN -sf %s" % os.path.join(_su_ppanel, "recover.sh") in _r, repr(_r[:400]))

    # The fresh ROOT path places recover.sh while the checkout is still root's, i.e. before its
    # chown — as install_root_tools already is. After it, a tarball or --src install had no way to
    # stage it at all. Comment lines stripped: this block's own prose names both.
    _su_code = "\n".join(_ln for _ln in _su_txt.splitlines() if not _ln.lstrip().startswith("#"))
    _su_fresh = _su_code[_su_code.index('info "[3/4] Registering the service'):]
    _su_fresh = _su_fresh[:_su_fresh.index("\nelse\n")]
    check("install.sh: the fresh root path installs the recovery command BEFORE the chown",
          "install_recovery_command" in _su_fresh
          and _su_fresh.index("install_recovery_command")
          < _su_fresh.index('chown -R "${PANEL_USER}:${PANEL_USER}" "${PANEL_DIR}"'),
          _su_fresh[:300])
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
# Matched on the FLAGS line rather than a single literal invocation: the bandit step now runs
# twice (SARIF for code scanning, JSON so errors[] can be checked) off one shared flag list, so
# pinning the exact string "bandit -r . tools/panel-helper" would break on a refactor that kept
# the coverage intact. What must hold is that the recursive walk names the helper explicitly —
# bandit -r globs *.py, and tools/panel-helper is Python with a shebang and no extension.
_bandit_flags = " ".join(l.strip() for l in _bandit_src.splitlines()
                         if "FLAGS=" in l or "bandit -r" in l)
check("coverage: panel-helper is bandit-scanned (bandit -r . globs *.py and would miss it)",
      "-r ." in _bandit_flags and "tools/panel-helper" in _bandit_flags, _bandit_flags[:140])
# ...and the errors[] guard: a file bandit cannot PARSE contributes zero results and exits 0, so
# without this the module holding the privilege boundary could be reported clean for not being
# read at all. Proven by execution with a syntax error injected into system_ops.py.
check("coverage: a file bandit could not read fails the job instead of reading as clean",
      "errors | length" in _bandit_src and "-f json" in _bandit_src,
      "no errors[] check after the bandit run")
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
# 222, was 221: /servers/<id>/retry-install is a genuinely new view. A failed install was a dead
# end — the row said "Failed", the reason lived in the install job's memory until the panel
# restarted, and the only way forward was to delete the server and start over, which also throws
# away the LinuxGSM config the failure usually asks you to change. The install job is re-entrant
# by construction, so this runs it again on the same row; it refuses a cause no retry can fix.
# 221, was 220: /api/installs is a genuinely new view — "is anything installing, and how far
# along", which nothing answered. The per-server endpoint below it says how ONE install is doing,
# which is all the Game Servers page needed because its row is already on screen; an install
# started from the Install a Server page had no row anywhere, so it showed a toast and then
# nothing for the next five to forty-five minutes. Access is get_user_servers(), which is also why
# the socket ping that drives the corner widget carries no payload.
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
# 223, was 222: /terminal/<id> is a genuinely new view — an interactive shell on a host, behind
# its own USE_TERMINAL permission rather than MANAGE_REMOTES, because a shell is every capability
# the session's account has at once and should be granted on purpose.
# 211, was 210: /password/change is a genuinely new view (the page an account with an admin-issued
# password is held on until it sets its own). This total exists to catch a view VANISHING during a
# move, so adding one is a deliberate bump — and url_map_baseline.json's diff is the record of what
# the new route actually is.
check("register_routes: every one of the 223 views is still accounted for",
      len(_rr_views) + _MOVED_VIEWS == 223,
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
check("docs: the fuzz harnesses were actually found, so the next check lists some",
      len(_harnesses) >= 1, "glob matched nothing — the next check would pass vacuously")
check("docs: every fuzz harness is listed in tests/fuzz/README.md",
      _harnesses and all(("fuzz_%s.py" % t) in _fuzz_readme for t in _harnesses),
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
for _mod in ("ssh_manager.py", "system_ops.py", "panel/core/terminal.py"):
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
    """The Location header a response carries after the middleware has rewritten it.

    load_config is stubbed for the call. __call__ resolves the mount as
    X-Forwarded-Prefix -> cfg["tailscale_mount"] -> the constructor argument, so the constructor
    argument is the LAST resort — and this helper used to say the opposite ("so the mount comes
    from the constructor argument"), which was true only on a machine with no mount configured.

    That made these four checks read the HOST's config.json. Green on CI and on a dev box, four
    failures on any real deployment served over a Tailscale mount — found by running this suite on
    the test VPS, where tailscale_mount is "/lgsm" and every expected "/panel/..." came back
    "/lgsm/...". A unit test has to mean the same thing on every machine."""
    _sr = _MwStart()

    def _app(_environ, start_response):
        start_response("302 FOUND", [("Location", loc)])
        return [b""]

    _mid = _mw.PrefixMiddleware(_app, prefix)
    _o_lc = _mw.load_config
    try:
        _mw.load_config = lambda: {}
        # Loopback + no X-Forwarded-Prefix + no configured mount, so the constructor argument is
        # what is under test.
        _mid({"REMOTE_ADDR": "127.0.0.1", "PATH_INFO": "/", "wsgi.url_scheme": "http"}, _sr)
    finally:
        _mw.load_config = _o_lc
    return dict(_sr.headers).get("Location")

eq("prefix: a path UNDER the mount is left alone", _mw_location("/panel/servers"), "/panel/servers")
eq("prefix: the mount itself is left alone", _mw_location("/panel"), "/panel")
eq("prefix: an unprefixed path gets the mount", _mw_location("/servers"), "/panel/servers")
eq("prefix: a path that merely STARTS WITH the mount is a different path, and gets prefixed",
   _mw_location("/panelserver"), "/panel/panelserver")


def _mw_location_cfg(loc, cfg, prefix="/panel"):
    """Same, but with a CONFIG the middleware will read."""
    _sr = _MwStart()

    def _app(_environ, start_response):
        start_response("302 FOUND", [("Location", loc)])
        return [b""]

    _mid = _mw.PrefixMiddleware(_app, prefix)
    _o_lc = _mw.load_config
    try:
        _mw.load_config = lambda: cfg
        _mid({"REMOTE_ADDR": "127.0.0.1", "PATH_INFO": "/", "wsgi.url_scheme": "http"}, _sr)
    finally:
        _mw.load_config = _o_lc
    return dict(_sr.headers).get("Location")


# The precedence nothing asserted, which is how the helper's wrong claim survived: a CONFIGURED
# mount beats the constructor argument. Asserting it makes the dependency visible instead of
# turning up as four failures on someone's real install.
eq("prefix: a configured tailscale_mount OUTRANKS the constructor argument",
   _mw_location_cfg("/servers", {"tailscale_mount": "/lgsm"}), "/lgsm/servers")
eq("prefix: ...and a mount of '/' is not a mount, so the argument stands",
   _mw_location_cfg("/servers", {"tailscale_mount": "/"}), "/panel/servers")
eq("prefix: ...and no mount key at all leaves the argument in charge",
   _mw_location_cfg("/servers", {}), "/panel/servers")

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
# The root-owned installer copy must come from the COMMIT, not from the working tree (which the
# panel user owns) and not from "$0" (the documented quick install is `curl … | bash`, where "$0"
# is the shell — an older form copied /usr/bin/bash into place). SCRIPT_PATH survives only as the
# fallback for a tree with no install.sh in it, and the shebang test is what keeps bash out.
check("install.sh: the root-owned installer copy is staged from the commit",
      "stage_root_source install.sh install.sh" in _inst)
check("install.sh: ...with SCRIPT_PATH only as a fallback, still shebang-checked",
      '${SCRIPT_PATH}' in _inst and "head -n1 \"${_istage}\" | grep -q '^#!.*sh'" in _inst)

# ── Disabling Tailscale Serve removes the mount it is actually ON ─────────────────────────────
# disableServe() hardcoded mount:'/'. `tailscale serve --remove /` exits 0 on a node whose mapping
# is at /lgsm-panel, so the panel reported success, cleared tailscale_setup_done and
# tailscale_mount, and left Serve running — with PrefixMiddleware then no longer prefixing URLs
# for a panel still served under the prefix.
_ts_tpl = open(os.path.join(_root, "templates", "tailscale.html"), encoding="utf-8").read()
check("tailscale.html: disableServe does not hardcode the mount",
      "action: 'disable', mount: '/'" not in _ts_tpl)
check("tailscale.html: the Mount Point field shows the route's default mount, not a fixed /",
      "value=\"{{ serve_default_mount }}\"" in _ts_tpl)
# The template reads two names only the route supplies; Jinja renders a forgotten one as a silent
# Undefined. So the route is held to passing them, by AST.
import ast as _ts_ast                                                              # noqa: E402
from panel.routes import tailscale as _ts_routes                                   # noqa: E402
_ts_rt_src = open(os.path.join(_root, "panel", "routes", "tailscale.py"), encoding="utf-8").read()
_ts_page_fn = next(n for n in _ts_ast.walk(_ts_ast.parse(_ts_rt_src))
                   if isinstance(n, _ts_ast.FunctionDef) and n.name == "tailscale_page")
_ts_rt_kw = {k.arg for n in _ts_ast.walk(_ts_page_fn) if isinstance(n, _ts_ast.Call)
             and getattr(n.func, "id", "") == "render_template" for k in n.keywords}
check("tailscale page: the route passes panel_routes and serve_default_mount to the template",
      {"panel_routes", "serve_default_mount"} <= _ts_rt_kw, repr(sorted(_ts_rt_kw)))
# Recommended Access built its direct URLs as http:// while the panel serves self-signed TLS by
# default. Both routes that ask for the suggestion now say which scheme the panel is serving.
_ts_sbb_calls = [n for n in _ts_ast.walk(_ts_ast.parse(_ts_rt_src)) if isinstance(n, _ts_ast.Call)
                 and getattr(n.func, "attr", "") == "suggest_best_bind"]
check("tailscale routes: every suggest_best_bind call passes the panel's scheme",
      len(_ts_sbb_calls) == 2 and all("scheme" in {k.arg for k in c.keywords} for c in _ts_sbb_calls),
      "%d call(s)" % len(_ts_sbb_calls))
_ts_eh = _ts_routes._effective_https
try:
    _ts_routes._effective_https = lambda cfg: True
    _ts_s1 = _ts_routes._panel_scheme({})
    _ts_routes._effective_https = lambda cfg: False
    _ts_s2 = _ts_routes._panel_scheme({})
finally:
    _ts_routes._effective_https = _ts_eh
eq("tailscale routes: the scheme follows whether the panel terminates its own TLS", (_ts_s1, _ts_s2),
   ("https", "http"))
# Enabling Serve at a mount another app holds REPLACES that app's mapping. The form offered "/"
# without looking; the setup wizard already moves the panel to /lgsm when "/" is taken.
_ts_grafana = type("I", (), {"serve_config": {"services": [{"url": "https://h.ts.net", "routes": [
    {"mount": "/", "target": "http://127.0.0.1:3000"}]}]}})()
eq("tailscale page: Enable does not offer a '/' another app already holds",
   _ts_routes._serve_default_mount(_ts_grafana, {}, 5000), "/lgsm")
_ts_panel_root = type("I", (), {"serve_config": {"services": [{"url": "https://h.ts.net", "routes": [
    {"mount": "/", "target": "http://127.0.0.1:5000"}]}]}})()
eq("tailscale page: ...while a '/' that is the panel's own, or free, stays '/' (control)",
   (_ts_routes._serve_default_mount(_ts_panel_root, {}, 5000),
    _ts_routes._serve_default_mount(type("I", (), {"serve_config": {}})(), {}, 5000)), ("/", "/"))

# The Serve card, RENDERED rather than grepped. Both defects below live in what the page says for
# a given state, and a substring gate cannot tell a branch from the comment that explains it.
from jinja2 import Environment as _TsEnv                                          # noqa: E402
_ts_card = _ts_tpl[_ts_tpl.index("<!-- Serve Config Status -->"):
                   _ts_tpl.index("<!-- Peers List -->")]
check("tailscale.html: the Serve card was isolated for the checks below",
      "Serve Configuration" in _ts_card and "disableServe" in _ts_card,
      "the card markers moved — re-point this gate, it is measuring nothing")


class _TsUser(object):
    is_superadmin = True


class _TsInfo(object):
    """Only the attributes the card reads. A dataclass field that does not exist is Jinja's
    Undefined (silently falsy), which is exactly the trap the unreadable flag has to survive."""

    def __init__(self, **kw):
        self.running, self.serve_config, self.serve_unreadable = True, {}, False
        self.__dict__.update(kw)


_ts_tmpl = _TsEnv().from_string(_ts_card)
_ts_svc = {"url": "https://host.example.ts.net", "funnel": False,
           "routes": [{"mount": "/panel", "target": "http://127.0.0.1:5000"}]}


def _ts_card_html(info, config=None):
    # panel_routes as the route computes it, from the host's config and the panel's port.
    from panel.ops import tailscale_integration as _ts_ti
    return _ts_tmpl.render(info=info, config=config or {}, current_user=_TsUser(),
                           panel_routes=_ts_ti.panel_serve_routes(info.serve_config, 5000))


# ...the mount the Disable button carries is the one the HOST reported, not the panel's
# recollection of one it set. config.tailscale_mount is empty for any mapping the panel did not
# create — an operator who ran `tailscale serve --bg --set-path /panel` by hand — and the button is
# shown for those too, so `or '/'` put back the exact value the comment above it forbids:
# `--remove /` exits 0 because removing an absent root mapping is not an error, so the toast said
# the mapping was removed, the audit row recorded a success, tailscale_setup_done was cleared, and
# Serve went on publishing the panel at /panel while the table beside the button still showed it.
_ts_by_hand = _ts_card_html(_TsInfo(serve_config={"services": [_ts_svc]}))
check("tailscale.html: Disable sends the mount the host reported, not a fallback '/'",
      'data-mount="/panel"' in _ts_by_hand,
      "the page displays /panel and the button would ask the host to remove something else")
_ts_disagree = _ts_card_html(_TsInfo(serve_config={"services": [_ts_svc]}),
                             {"tailscale_mount": "/lgsm"})
check("tailscale.html: ...and the page's own value wins over a stale stored one",
      'data-mount="/panel"' in _ts_disagree and 'data-mount="/lgsm"' not in _ts_disagree,
      "the stored mount is sent while the table renders a different one")
_ts_stored_only = _ts_card_html(
    _TsInfo(serve_config={"services": [{"url": "https://h.ts.net", "funnel": False, "routes": []}]}),
    {"tailscale_mount": "/lgsm", "tailscale_setup_done": True})
check("tailscale.html: ...with the stored mount still the fallback when no route came back",
      'data-mount="/lgsm"' in _ts_stored_only, _ts_stored_only[:200])
# ...and "the host reported" means the route that proxies the PANEL. It was services[0].routes[0],
# and Tailscale lists "/" first: where another app holds "/" and the panel sits at /lgsm, Disable
# targeted the other app.
_ts_shared = _ts_card_html(_TsInfo(serve_config={"services": [
    {"url": "https://host.example.ts.net", "funnel": True, "routes": [
        {"mount": "/", "target": "http://127.0.0.1:3000"},
        {"mount": "/lgsm", "target": "https+insecure://127.0.0.1:5000"}]}]}))
check("tailscale.html: Disable carries the panel's mount, not another app's '/' listed first",
      'data-mount="/lgsm"' in _ts_shared and 'data-mount="/"' not in _ts_shared,
      repr([ln.strip() for ln in _ts_shared.splitlines() if "data-mount" in ln]))
_ts_other_only = _ts_card_html(_TsInfo(serve_config={"services": [
    {"url": "https://host.example.ts.net", "funnel": False, "routes": [
        {"mount": "/", "target": "http://127.0.0.1:3000"}]}]}))
check("tailscale.html: ...and a node serving only another app offers no Disable at all",
      'data-action="disableServe"' not in _ts_other_only,
      repr([ln.strip() for ln in _ts_other_only.splitlines() if "data-mount" in ln]))

# ...and an unread Serve config is not announced as "nothing is configured". serve_config is {} for
# both "nothing is published" and "`tailscale serve status` was refused" (the panel's account is
# not the tailscale operator), and the card stated the first as a fact — on a page that was itself
# being served over the very mapping it was reporting as absent.
_ts_denied = _ts_card_html(_TsInfo(serve_unreadable=True))
check("tailscale.html: a Serve config the panel could not read is not reported as empty",
      "No Serve routes configured yet." not in _ts_denied and "couldn't read" in _ts_denied,
      " ".join(_ts_denied.split())[-160:])
_ts_none = _ts_card_html(_TsInfo())
check("tailscale.html: ...while a host that answered with none still says so (positive control)",
      "No Serve routes configured yet." in _ts_none and "couldn't read" not in _ts_none,
      " ".join(_ts_none.split())[-160:])
# The flag is read the UNREADABLE way round on purpose: a TailscaleInfo without it leaves Jinja an
# Undefined, which is silently falsy — so a missing flag has to fall back to the positive wording,
# never to telling every healthy host its Serve config could not be read.


class _TsInfoOld(object):
    running, serve_config = True, {}


check("tailscale.html: ...and an info object with no flag at all keeps the positive wording",
      "No Serve routes configured yet." in _ts_card_html(_TsInfoOld()),
      "a forgotten attribute would tell every host its Serve config is unreadable")
_ts_down = _ts_card_html(_TsInfo(running=False, serve_unreadable=True))
check("tailscale.html: ...and a stopped daemon still reads as stopped, not as unreadable",
      "Tailscale is not running." in _ts_down, " ".join(_ts_down.split())[-160:])
# The Accept Routes row: RouteAll, which is None when the prefs could not be read — and that is
# not "No". (The row used to print the TUN flag as if it were this.)
_ts_nd = _TsEnv().from_string(_ts_tpl[_ts_tpl.index("<!-- Node Details -->"):
                                      _ts_tpl.index("<!-- Peer Reachability Checker -->")])


def _ts_ar_row(v):
    _h = _ts_nd.render(info=_TsInfo(accept_routes=v, funnel_enabled=False, tailscale_ips=[]),
                       ts_detail=True)
    return " ".join(_h[_h.index("Accept Routes"):].split("</tr>")[0].split())


check("tailscale.html: unreadable prefs show Accept Routes as unknown, not 'No'",
      "No" not in _ts_ar_row(None) and "Yes" not in _ts_ar_row(None), _ts_ar_row(None))
check("tailscale.html: ...while a read pref says Yes / No (control)",
      "Yes" in _ts_ar_row(True) and "No" in _ts_ar_row(False)
      and "Yes" not in _ts_ar_row(False), "%s | %s" % (_ts_ar_row(True), _ts_ar_row(False)))
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
# The sweeps below are all "no bad key anywhere". Fed an empty catalog every one of them passes —
# two empty sets compare equal, `not {}` is True, and a missing-keys diff over nothing is empty.
# Measured by pointing tools/i18n_scan's globs at "*.MUTATED": the suite reported 1888/1888 with
# all three i18n gates green, having scanned zero files. Floors, not inventories.
_i18n_seen = {_l: len(glob.glob(os.path.join(_i18n_dir, _l, "*.json"))) for _l in ("es", "fr")}
check("sweep: the translations/ scan found catalog files to read",
      all(_n >= 4 for _n in _i18n_seen.values()),
      "%s — every i18n gate below would pass vacuously" % _i18n_seen)
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
# The scanner has its own globs, and proof B above was exactly those drifting while templates/
# and static/js/ were untouched. Assert it actually read something before trusting its answer.
_i18n_found, _ = _i18n_scan.scan_templates(os.path.join(_root, "templates"))
check("sweep: i18n_scan read the templates (its own globs can drift)",
      len(_i18n_found) >= 400,
      "%d translatable strings — the gates below would pass on an empty scan" % len(_i18n_found))
_i18n_js_seen = _i18n_scan.scan_js(os.path.join(_root, "static", "js"))
check("sweep: ...and the JS", len(_i18n_js_seen) >= 40,
      "%d strings — the JS catalog gate would pass on an empty scan" % len(_i18n_js_seen))
_i18n_gaps = _i18n_scan.missing("es",
                                template_dir=os.path.join(_root, "templates"),
                                translation_dir=_i18n_dir)
check("i18n: every translatable template string is in the catalog",
      not _i18n_gaps,
      "%d untranslated: %s" % (len(_i18n_gaps),
                               "; ".join("%r in %s" % (_k, ",".join(sorted(_v)))
                                         for _k, _v in sorted(_i18n_gaps.items())[:4])))

# ── ...and no string is welded to a {{ }} where no catalog entry could ever reach it ───────────
# The gate above asks whether a translatable string is IN the catalog. This one asks whether it
# could be used if it were. Jinja emits one contiguous text run, so `{{ n }} entr{{ 'y' if ... }}`
# reaches the browser as the single node "7 entries" — different for every request, matching no
# key, and no catalog entry can fix it; the template has to put the static half in its own
# element. Ten strings were in that state, so a Spanish or French user read "7 entries",
# "3 rules", "5 left" and "2 Source servers" in English on pages that were otherwise translated.
#
# A dynamic string that IS in the catalog is inert rather than broken — it is translated wherever
# it appears as a node of its own — so only the ones with no entry are failures.
_i18n_dyn_cat = _i18n_scan.load_catalog("es", translation_dir=_i18n_dir)
_, _i18n_dyn = _i18n_scan.scan_templates(os.path.join(_root, "templates"))
_i18n_unreachable = {_k: _v for _k, _v in _i18n_dyn.items() if _k not in _i18n_dyn_cat}
check("i18n: no translatable string is glued to a {{ }} with no catalog entry to reach it",
      not _i18n_unreachable,
      "%d unreachable — give the static half its own element: %s"
      % (len(_i18n_unreachable),
         "; ".join("%r in %s" % (_k, ",".join(sorted(_v)))
                   for _k, _v in sorted(_i18n_unreachable.items())[:4])))

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

# ── Every SGR code the server keeps has to be STYLED, or it is dropped in silence ──────────────
# Three layers have to agree and nothing made them: terminal.py's _SGR_ALLOWED decides which codes
# survive, server_detail.js emits `ansi-<code>` for every code it is handed, and panel.css decides
# what that class looks like. A code allowed by the first two with no rule in the third renders as
# PLAIN TEXT — no error, no warning, just the emphasis quietly gone.
#
# It had happened to nine of them: reverse video (7) and the whole bright-background range
# (100-107). Measured in a browser against the real stylesheet — .ansi-41 painted
# rgb(127,29,29) and .ansi-101 painted rgba(0,0,0,0).
#
# Derived from the allowlist rather than listed here, so widening _SGR_ALLOWED fails this until
# the rule exists.
from panel.core import terminal as _sgr_term  # noqa: E402
_sgr_css = {int(_m) for _m in re.findall(r"\.ansi-(\d+)\s*\{", _css_raw)}
# The codes that TURN SOMETHING OFF need no rule: the server applies them itself (39 and 49 strip
# the colour from the run) or they end a run, and the JS never emits a class for 0.
_SGR_RESETS = {0, 21, 22, 23, 24, 27, 29, 39, 49}
_sgr_unstyled = sorted(c for c in _sgr_term._SGR_ALLOWED if c not in _SGR_RESETS and c not in _sgr_css)
check("console: every SGR code the server keeps has a CSS rule", not _sgr_unstyled,
      "allowed and emitted but styled by nothing: %s" % _sgr_unstyled)
check("console: ...and no rule exists for a code the server strips",
      not sorted(c for c in _sgr_css if c not in _sgr_term._SGR_ALLOWED),
      "styled but never emitted: %s" % sorted(c for c in _sgr_css if c not in _sgr_term._SGR_ALLOWED))
# Reverse video is the one that cannot be a plain colour swap in CSS: currentColor paints the
# background with the run's own colour, and the glyphs need the console's background put back —
# through -webkit-text-fill-color, because `color` is what currentColor reads.
check("console: reverse video actually inverts rather than doing nothing",
      "background: currentColor" in _css_raw and "-webkit-text-fill-color" in _css_raw,
      ".ansi-7 does not swap anything")


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
    """recover.sh with the WHOLE of its detection pointed at the sandbox, and list-users keeping
    it read-only.

    All three inputs, not just the scan. recover.sh consults the system unit, then the user unit,
    then the /home scan — so on a host that really has a panel unit installed the first branch won
    and these checks silently exercised something they were not written for. Measured on a
    deployed host: recover.sh answered "Using <the test's own directory> (service user lgsmpanel)",
    mixing a directory from one branch with a service user from another, and the ambiguity checks
    below failed for a reason that had nothing to do with ambiguity. PANEL_DIR is cleared too: it
    outranks every branch, and inheriting a stray one from the environment would skip detection
    entirely."""
    _env = {k: v for k, v in os.environ.items() if k != "PANEL_DIR"}
    _env.update({"PANEL_RECOVER_HOMES": _rv_root,
                 "PANEL_RECOVER_SYSTEM_UNIT": os.path.join(_rv_root, "_no_system_unit"),
                 "PANEL_RECOVER_USER_UNIT": os.path.join(_rv_root, "_no_user_unit"),
                 "HOME": os.path.join(_rv_root, "_nohome")})
    return _rv_sub.run(["bash", os.path.join(_root, "recover.sh"), "list-users"],
                       capture_output=True, text=True, timeout=60, env=_env)


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
# ── a negative sentinel must be paired with its positive one ─────────────────────────────────
# The probes in this codebase are `cmd && echo 'FOUND' || echo 'NOTFOUND'`, and a caller that
# tests only the NEGATIVE token inverts its answer on an EMPTY read: `"NOTFOUND" not in ""` is
# True. run_command returns ("", "...timed out", -1) rather than raising for the local and
# Tailscale transports, so "" is the ordinary unreachable case, not an exotic one.
#
# Three sites read that way at once: a Tailscale check that called an unreachable host
# "installed", an interface probe that named an interface it never saw, and a bootstrap `id`
# probe that said the account already existed and therefore SKIPPED creating it. The fourth site
# was already correct and is the idiom: `"NOTEXISTS" not in idout and "EXISTS" in idout`.
import ast as _sent_ast
_sent_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_sent_bad, _sent_seen = [], 0
for _dirpath, _dirnames, _filenames in os.walk(os.path.join(_sent_root, "panel")):
    _dirnames[:] = [_d for _d in _dirnames if _d != "__pycache__"]
    for _fn in sorted(_filenames):
        if not _fn.endswith(".py"):
            continue
        _rel = os.path.relpath(os.path.join(_dirpath, _fn), _sent_root)
        _tree = _sent_ast.parse(open(os.path.join(_dirpath, _fn), encoding="utf-8").read())
        for _n in _sent_ast.walk(_tree):
            if not isinstance(_n, _sent_ast.Compare) or len(_n.ops) != 1:
                continue
            if not isinstance(_n.ops[0], _sent_ast.NotIn):
                continue
            _lhs = _n.left
            if not (isinstance(_lhs, _sent_ast.Constant) and isinstance(_lhs.value, str)
                    and _lhs.value.startswith("NOT") and len(_lhs.value) > 3):
                continue
            _sent_seen += 1
            _positive = _lhs.value[3:]          # "NOTINSTALLED" -> "INSTALLED"
            # The positive token must be tested somewhere in the same enclosing expression.
            _ok = False
            for _outer in _sent_ast.walk(_tree):
                if not isinstance(_outer, _sent_ast.BoolOp):
                    continue
                if not any(_c is _n for _c in _sent_ast.walk(_outer)):
                    continue
                for _c in _sent_ast.walk(_outer):
                    if (isinstance(_c, _sent_ast.Compare) and len(_c.ops) == 1
                            and isinstance(_c.ops[0], _sent_ast.In)
                            and isinstance(_c.left, _sent_ast.Constant)
                            and _c.left.value == _positive):
                        _ok = True
            if not _ok:
                _sent_bad.append("%s:%d  %r without a matching %r"
                                 % (_rel, _n.lineno, _lhs.value, _positive))

check("sweep: the negative-sentinel scan found probes to check", _sent_seen >= 3,
      "found %d" % _sent_seen)
check("probes: a negative sentinel is always paired with its positive one",
      not _sent_bad,
      "an EMPTY read passes these, inverting the answer: %s" % "; ".join(_sent_bad))

# ── a suite's REPORTER must not be the thing that fails ──────────────────────────────────────
# Every suite here ends by printing its results. That loop did `"  [%s]" % detail`, which raises
# TypeError when detail is a tuple or an int — and it only ever runs that branch for a FAILING
# check. So a check written with a non-string detail was green forever and, the one time it
# mattered, printed a traceback instead of its own name, took the tally with it, and skipped the
# suite's cleanup(). Seen twice in one day, in two different suites.
#
# Two gates, because either alone can be worked around: the reporter must use the tuple form, and
# no check() call may hand it something that is obviously not a string.
import ast as _rep_ast
_REPORTER_SUITES = ["tests/unit_test.py", "tests/smoke_test.py", "tests/rbac_test.py",
                    "tests/template_actions_test.py", "tests/input_validation_test.py",
                    "tests/manage_test.py", "tests/setup_wizard_test.py"]
_rep_fragile, _rep_seen = [], 0
for _f in _REPORTER_SUITES:
    _src = open(os.path.join(_root, _f), encoding="utf-8").read()
    _rep_seen += 1
    # the safe forms: "% (detail,)" or an explicit str()/repr() around it
    if ('"   [%s]" % detail' in _src and '"   [%s]" % (detail,)' not in _src
            and '% str(detail)' not in _src):
        _rep_fragile.append(_f)
check("suites: the result printer was actually read", _rep_seen == len(_REPORTER_SUITES),
      "read %d of %d" % (_rep_seen, len(_REPORTER_SUITES)))
check("suites: no result printer raises on a non-string detail",
      not _rep_fragile,
      "a FAILING check in these prints a TypeError instead of its name: %s" % ", ".join(_rep_fragile))

_det_bad = []
for _f in _REPORTER_SUITES + ["tests/unit/part01.py", "tests/unit/part02.py",
                              "tests/unit/part03.py", "tests/unit/part04.py",
                              "tests/unit/part05.py", "tests/unit/part06.py"]:
    _tree = _rep_ast.parse(open(os.path.join(_root, _f), encoding="utf-8").read())
    for _n in _rep_ast.walk(_tree):
        if not (isinstance(_n, _rep_ast.Call) and getattr(_n.func, "id", "") == "check"):
            continue
        if len(_n.args) < 3:
            continue
        _d = _n.args[2]
        # Only a MULTI-ELEMENT TUPLE is a hazard: "%s" % (1, 2) raises, while a list, an int,
        # a dict, None and a 1-tuple all format fine. Flagging len() or sorted() here would be
        # noise — checked directly rather than assumed.
        if isinstance(_d, _rep_ast.Tuple) and len(_d.elts) > 1:
            _det_bad.append("%s:%d passes a %d-tuple" % (_f, _n.lineno, len(_d.elts)))
check("suites: no check() hands its reporter something that is not a string",
      not _det_bad, "; ".join(_det_bad[:6]))

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

# ── The value that keys the login throttle must not be chosen by the client ───────────────────
# client_ip() keys the login throttle, the API-token throttle, the audit log, data/auth.log (which
# the panel-login fail2ban jail parses) and the 7-day auto-block counts. WHOM to trust and WHAT to
# read are different questions and only the first was being asked: the answer to the second was
# X-Forwarded-For's FIRST hop, the one element of that header a client always controls, because a
# proxy can only append to its right.
#
# Measured through the real /login with the README's own deployment: twenty failed logins from one
# client, each with a different X-Forwarded-For, were never rate-limited and left twenty separate
# throttle keys. With a constant value the same loop blocked at attempt 8.
from panel.security import auth as _ip_auth                                       # noqa: E402
from flask import Flask as _IpFlask                                               # noqa: E402
_ip_app = _IpFlask(__name__)


def _ip_for(headers, remote="127.0.0.1", trust_proxy=False, proxy_fix_orig=None, root_peer=True):
    # root_peer: the loopback caller is tailscaled (a root-owned socket), the Serve shape these
    # checks are about. A non-root loopback caller is not trusted at all — see part02.
    _ip_app.config["_TRUST_PROXY"] = trust_proxy
    env = {"REMOTE_ADDR": remote}
    if proxy_fix_orig is not None:
        env["werkzeug.proxy_fix.orig"] = {"REMOTE_ADDR": proxy_fix_orig}
    _saved_lpt = _ip_auth._loopback_proxy_trusted
    _ip_auth._loopback_proxy_trusted = lambda: root_peer
    try:
        with _ip_app.test_request_context("/", headers=headers, environ_overrides=env):
            return _ip_auth.client_ip()
    finally:
        _ip_auth._loopback_proxy_trusted = _saved_lpt


# X-Forwarded-For's LAST hop wins, and X-Real-IP is only the fallback. The order used to be the
# other way round, on the premise that a proxy setting X-Real-IP has overwritten whatever the
# client sent. True of nginx and Caddy; NOT true of Tailscale Serve, which this panel enables by
# itself and which proxies to loopback — so `behind_proxy` is True with no configuration, and
# Serve's addProxyForwardedHeaders sets only the X-Forwarded-* trio and passes a client-supplied
# X-Real-IP straight through. That made the login throttle key client-chosen on the DEFAULT
# deployment: a fresh bucket per request, so LOGIN_MAX_FAILS was never reached.
eq("client_ip: the LAST X-Forwarded-For hop wins over a client-supplied X-Real-IP",
   _ip_for({"X-Real-IP": "9.9.9.9", "X-Forwarded-For": "100.64.0.5"}), "100.64.0.5")
eq("client_ip: X-Forwarded-For takes the LAST hop, not the first",
   _ip_for({"X-Forwarded-For": "9.9.9.9, 198.51.100.4, 100.64.0.5"}), "100.64.0.5")
eq("client_ip: X-Real-IP is still read when there is no X-Forwarded-For at all",
   _ip_for({"X-Real-IP": "100.64.0.5"}), "100.64.0.5")
# A key space is only bounded while the values are addresses — anything else is a client picking
# its own throttle bucket, so it falls through to the socket peer.
eq("client_ip: a non-address X-Forwarded-For hop is not a bucket key",
   _ip_for({"X-Forwarded-For": "not-an-ip"}), "127.0.0.1")
eq("client_ip: a non-address X-Real-IP is not a bucket key",
   _ip_for({"X-Real-IP": "../../etc/passwd"}), "127.0.0.1")
eq("client_ip: a bracketed IPv6 hop with a port is still read",
   _ip_for({"X-Forwarded-For": "[2001:db8::5]:443"}), "2001:db8::5")
eq("client_ip: a direct connection ignores both headers",
   _ip_for({"X-Real-IP": "100.64.0.5", "X-Forwarded-For": "9.9.9.9"}, remote="203.0.113.9"),
   "203.0.113.9")
# With trust_proxy, ProxyFix has already rewritten remote_addr FROM the header being judged — so
# the original socket peer is what decides, and the last X-Forwarded-For hop is what is read.
eq("client_ip: behind a declared proxy, the header the proxy sets wins over the rewritten peer",
   _ip_for({"X-Real-IP": "9.9.9.9", "X-Forwarded-For": "100.64.0.5"},
           remote="9.9.9.9", trust_proxy=True, proxy_fix_orig="127.0.0.1"), "100.64.0.5")
eq("client_ip: a NON-root loopback caller's headers are ignored (a local account, not Serve)",
   _ip_for({"X-Real-IP": "9.9.9.9", "X-Forwarded-For": "100.64.0.5"}, root_peer=False),
   "127.0.0.1")
eq("client_ip: ...but a declared proxy (trust_proxy) is still believed from any peer",
   _ip_for({"X-Forwarded-For": "100.64.0.5"}, trust_proxy=True, root_peer=False), "100.64.0.5")
eq("client_ip: no headers at all -> the socket address",
   _ip_for({}, remote="203.0.113.9"), "203.0.113.9")
# ...and the deployment guide has to set the header it tells the panel to read.
_ip_readme = open(os.path.join(_root, "README.md"), encoding="utf-8").read()
check("README: the nginx block sets X-Forwarded-For rather than passing the client's through",
      "proxy_add_x_forwarded_for" in _ip_readme,
      "nginx forwards whatever the client sent")

# ── Secure cookies ask whether the panel is REACHED over HTTPS ────────────────────────────────
# The flag mirrored _effective_https's Tailscale case and not its PROXY case, so the deployment
# the README recommends issued the session cookie and the 3-day remember token with no Secure
# flag. And site_domain — a hostname typed into the setup wizard — counted as evidence of TLS,
# which marked the cookies Secure on a panel serving plain HTTP: the browser drops them, the
# password is right, and / bounces to /login forever.
import app as _ck_app                                                              # noqa: E402
import inspect as _ck_inspect                                                       # noqa: E402
_ck_expr = _ck_inspect.getsource(_ck_app._https_ready)
for _label, _cfg, _want in (
        ("fresh install, self-signed TLS", {"use_https": True}, True),
        ("Tailscale Serve in front", {"use_https": True, "tailscale_setup_done": True}, True),
        ("reverse proxy in front", {"use_https": False, "trust_proxy": True}, True),
        ("reverse proxy + a site_domain", {"use_https": False, "trust_proxy": True,
                                           "site_domain": "p.example"}, True),
        ("no TLS anywhere, domain typed in setup", {"use_https": False,
                                                    "site_domain": "p.example"}, False)):
    _got = _ck_app._https_ready(_cfg)
    check("cookies: Secure is %s for %s" % (_want, _label), _got is _want, "got %s" % _got)
check("cookies: the Secure predicate reads trust_proxy", "trust_proxy" in _ck_expr, _ck_expr)
# ── Tailscale Serve stands the panel's own TLS down ONLY on a loopback bind ──────────────────
# It stood down whenever Serve had been set up. The wizard stores bind_host 0.0.0.0 by default and
# nothing that marks Serve done changes it, so the next restart served cleartext HTTP on the public
# interface — passwords and Bearer tokens in the clear. Serve must follow whichever scheme is used.
# An UNSET bind is judged by what boot resolves it to, not by the empty string: with Serve proxying,
# boot binds 127.0.0.1, and treating "" as public switched those installs (the live one among them)
# to self-signed HTTPS for no gain, with Serve reachable only if a re-point succeeded at every boot.
_ts_sbb = _ck_app.ts.suggest_best_bind
try:
    for _label, _bind, _resolves, _want_tls in (
            ("0.0.0.0 (public + tailnet)", "0.0.0.0", None, True),
            ("an unset bind that resolves public (Serve down)", "", "0.0.0.0", True),
            ("an unset bind that resolves loopback (Serve up)", "", "127.0.0.1", False),
            ("a public address", "203.0.113.5", None, True),
            ("127.0.0.1", "127.0.0.1", None, False),
            ("::1", "::1", None, False)):
        _ck_app._RESOLVED_BIND.clear()
        _ck_app.ts.suggest_best_bind = (lambda _r: lambda _p=5000: {"bind_host": _r})(_resolves)
        _ts_cfg = {"use_https": True, "tailscale_setup_done": True, "bind_host": _bind}
        check("https: with Serve set up and bind %s, own TLS is %s" % (_label, _want_tls),
              _ck_app._effective_https(_ts_cfg) is _want_tls, repr(_ck_app._effective_https(_ts_cfg)))
        check("https: ...and Serve is pointed at the scheme actually served (%s)" % _label,
              _ck_app._ts_backend_scheme(_ts_cfg) == ("https+insecure" if _want_tls else "http"),
              _ck_app._ts_backend_scheme(_ts_cfg))
finally:
    _ck_app.ts.suggest_best_bind = _ts_sbb
    _ck_app._RESOLVED_BIND.clear()
# ...and boot binds the same address the TLS decision was made for (one resolver, not two).
with open(_ck_app.__file__, encoding="utf-8") as _ts_fh:
    _ts_main = _ts_fh.read()
_ts_boot = _ts_main[_ts_main.index('if __name__ == "__main__":'):]
check("https: boot's bind comes from _resolved_bind, the same answer the TLS decision reads",
      "host = _resolved_bind(cfg)" in _ts_boot and "suggest_best_bind" not in _ts_boot,
      "boot resolves its bind separately — the scheme Serve is pointed at can disagree with it")
check("cookies: ...and not site_domain, which is not evidence of TLS",
      "site_domain" not in _ck_expr, _ck_expr)

# ── the mount prefix is a PATH, and it is matched as one ──────────────────────────────────────
# _may_trust_header decides WHO may set X-Forwarded-Prefix; nothing constrained WHAT it could say,
# so a trusted-source request could set SCRIPT_NAME to "//evil.example" and have every url_for()
# on the page it got back, and the Location of every redirect, point off-site — the exact harm the
# docstring says the source rule prevents. And the incoming PATH_INFO strip was a bare substring
# test, so on mount /panel every page was served a second time outside the mount: /panelserver/1
# arrived as SCRIPT_NAME=/panel PATH_INFO=server/1 and answered 200.
from panel.core.middleware import PrefixMiddleware as _PM                          # noqa: E402
for _raw, _want in (("/lgsm", "/lgsm"), ("/ok/", "/ok"), ("", ""),
                    ("//evil.example", ""), ("https://evil.example", ""),
                    ("/a/../../b", ""), ("/x\ny", ""), ("/a b", "")):
    eq("prefix: %r -> %r" % (_raw, _want), _PM._clean_prefix(_raw), _want)

_pm_seen = []


def _pm_app(environ, start_response):
    _pm_seen.append((environ.get("SCRIPT_NAME"), environ.get("PATH_INFO")))
    start_response("200 OK", [])
    return [b""]


_pm = _PM(_pm_app, "/panel")
_o_lc = _PM.__module__ and __import__("panel.core.middleware", fromlist=["load_config"])
_pm_o_cfg = _o_lc.load_config
_o_lc.load_config = lambda: {"tailscale_mount": "/panel"}
try:
    for _path, _want in (("/panel/login", ("/panel", "/login")),
                         ("/panel", ("/panel", "/")),
                         ("/panelserver/1", ("/panel", "/panelserver/1")),
                         ("/paneling", ("/panel", "/paneling"))):
        _pm_seen.clear()
        _pm({"PATH_INFO": _path, "REMOTE_ADDR": "203.0.113.9", "SCRIPT_NAME": ""},
            lambda *a, **k: None)
        eq("prefix: %r is routed as %r" % (_path, _want[1]), _pm_seen[-1], _want)
    # ...and a hostile header, all the way through __call__ — not just through _clean_prefix,
    # which a test can call while the middleware has stopped calling it.
    for _hostile in ("//evil.example", "https://evil.example"):
        _pm_seen.clear()
        _pm({"PATH_INFO": "/login", "REMOTE_ADDR": "127.0.0.1", "SCRIPT_NAME": "",
             "HTTP_X_FORWARDED_PREFIX": _hostile}, lambda *a, **k: None)
        check("prefix: X-Forwarded-Prefix %r never becomes SCRIPT_NAME" % _hostile,
              _pm_seen and _pm_seen[-1][0] != _hostile, str(_pm_seen[-1:]))
finally:
    _o_lc.load_config = _pm_o_cfg

# ── disabling 2FA revokes its backup codes, on EVERY path ─────────────────────────────────────
# Two web paths clear them and say so; the CLI was the one that did not, leaving bcrypt hashes of
# credentials the operator had just revoked in panel.db.
import ast as _2fa_ast                                                             # noqa: E402
_2fa_sources = {
    "manage.py cmd_disable_2fa": open(os.path.join(_root, "manage.py"), encoding="utf-8").read(),
    "tags.py": open(os.path.join(_root, "panel", "routes", "tags.py"), encoding="utf-8").read(),
    "admin_notifications.py": open(os.path.join(_root, "panel", "routes",
                                                "admin_notifications.py"), encoding="utf-8").read(),
}
_2fa_missing = []
for _name, _src in _2fa_sources.items():
    for _fn in _2fa_ast.walk(_2fa_ast.parse(_src)):
        if not isinstance(_fn, (_2fa_ast.FunctionDef,)):
            continue
        _body = _2fa_ast.get_source_segment(_src, _fn) or ""
        if "totp_enabled = False" in _body and "backup_codes = \"\"" not in _body:
            _2fa_missing.append("%s:%s" % (_name, _fn.name))
check("2FA: every path that disables it also clears the backup codes", not _2fa_missing,
      "left behind by: %s" % _2fa_missing)

# ── The dump salvage must KEEP what it read ───────────────────────────────────────────────────
# The per-statement guard only wrapped dst.execute(); the error a corrupt page raises comes from
# the iterdump GENERATOR, so it escaped that guard, unwound the `with dst:` and was caught by the
# outer handler as a total failure. Measured on a 169-page database with ONE page corrupted in the
# middle: 1477 statements were readable, zero were kept, the rebuild came out 0 bytes, and repair()
# said "could not repair" — the exact case this function exists for. Built here rather than
# described, because "recovers cleanly readable rows" was a docstring for a long time.
import sqlite3 as _dbm_sqlite                                                      # noqa: E402
import inspect as _tg_inspect                                                      # noqa: E402
import json as _json                                                               # noqa: E402
import importlib.util as _dbm_ilu                                                  # noqa: E402
_dbm_spec = _dbm_ilu.spec_from_file_location("dbm_probe", os.path.join(_root, "db_maintenance.py"))
_dbm = _dbm_ilu.module_from_spec(_dbm_spec)
_dbm_spec.loader.exec_module(_dbm)

_dbm_tmp = _tempfile.mkdtemp(prefix="dbrebuild-")
try:
    _dbm_src = os.path.join(_dbm_tmp, "src.db")
    _c = _dbm_sqlite.connect(_dbm_src)
    _c.execute("CREATE TABLE user (id INTEGER PRIMARY KEY, name TEXT)")
    _c.executemany("INSERT INTO user (name) VALUES (?)", [("u%05d" % i,) for i in range(4000)])
    _c.commit()
    _c.close()
    _dbm_size = os.path.getsize(_dbm_src)
    # One bad page in the middle — the one-bad-sector case, not a shredded file.
    with open(_dbm_src, "r+b") as _fh:
        _fh.seek(_dbm_size // 2)
        _fh.write(b"\xde\xad\xbe\xef" * 256)
    _dbm_dst = os.path.join(_dbm_tmp, "rebuilt.db")
    _dbm_ok = _dbm._rebuild_via_dump(_dbm_src, _dbm_dst)
    _dbm_rows = 0
    if os.path.exists(_dbm_dst):
        try:
            _rc = _dbm_sqlite.connect(_dbm_dst)
            _dbm_rows = _rc.execute("SELECT COUNT(*) FROM user").fetchone()[0]
            _rc.close()
        except _dbm_sqlite.DatabaseError:
            _dbm_rows = -1
    check("db rebuild: a corrupt page in the middle does not discard the rows already read",
          _dbm_ok and _dbm_rows > 100, "ok=%s rows=%s" % (_dbm_ok, _dbm_rows))
    # ...and an intact database still rebuilds completely.
    _dbm_src2 = os.path.join(_dbm_tmp, "good.db")
    _c = _dbm_sqlite.connect(_dbm_src2)
    _c.execute("CREATE TABLE user (id INTEGER PRIMARY KEY, name TEXT)")
    _c.executemany("INSERT INTO user (name) VALUES (?)", [("u%d" % i,) for i in range(50)])
    _c.commit(); _c.close()
    _dbm_dst2 = os.path.join(_dbm_tmp, "rebuilt2.db")
    _dbm._rebuild_via_dump(_dbm_src2, _dbm_dst2)
    _rc = _dbm_sqlite.connect(_dbm_dst2)
    _dbm_all = _rc.execute("SELECT COUNT(*) FROM user").fetchone()[0]
    _rc.close()
    eq("db rebuild: an intact database still rebuilds in full", _dbm_all, 50)
finally:
    _shutil.rmtree(_dbm_tmp, ignore_errors=True)

# ── A failed priming poll must not mark the bot primed ────────────────────────────────────────
# telegram_get_updates answers None on a network error, on a 409 (a second poller) and on
# ok:false. `primed = True` ran regardless, leaving offset=None, so the next poll asked Telegram
# for every unconfirmed update — and Telegram holds those for 24 hours. The window this runs in is
# the one most likely to fail: the process has just restarted from a self-update, so a
# `/stop codserver` sent hours earlier stops a running server.
from panel.services.bots import telegram as _tgm                                   # noqa: E402
_tg_src = _tg_inspect.getsource(_tgm)
_tg_prime = _tg_src[_tg_src.index("if not primed:"):_tg_src.index("updates = notifications.telegram_get_updates(token, offset=offset")]
check("telegram: a priming poll that did not answer leaves the bot UNPRIMED",
      "if latest is None:" in _tg_prime and "continue" in _tg_prime.split("if latest is None:")[1].split("primed = True")[0],
      _tg_prime)

# ── /console must not print the "not running" sentinel as console output ──────────────────────
# `echo NO_SESSION` goes to STDOUT, so out == "NO_SESSION" and the `if not rows` guard could never
# fire: the command that exists to answer "why did the start fail?" answered NO_SESSION. rc was
# unpacked and never read, while the comment beside it claimed the case was handled.
from panel.services.bots import commands as _botcmd                                # noqa: E402
_bc_src = _tg_inspect.getsource(_botcmd._console_text)
check("bots: /console reads capture_console's rc instead of printing NO_SESSION",
      "NO_SESSION" in _bc_src and "rc != 0" in _bc_src, _bc_src[:200])
# ...and only the sentinel (rc 3 + NO_SESSION) means "not running". Every other non-zero rc was
# answered the same way — a transport timeout (rc -1, which the local and tailscale transports
# return without raising) or a `sudo -u` refusal told the admin the server wasn't running when the
# panel had never reached it. Driven, not grepped.
import contextlib as _bc_ctx                                                       # noqa: E402
from panel.ops.ssh_manager import game as _bc_game                                 # noqa: E402
_bc_app = type("A", (), {"app_context": lambda self: _bc_ctx.nullcontext()})()
_bc_gs = NS(name="Rust", remote=None, short_name="rustserver", lgsm_name="rustserver")
_bc_saved = (_botcmd._find_server, _bc_game.capture_console)
try:
    _botcmd._find_server = lambda arg: (_bc_gs, None)
    _bc_game.capture_console = lambda *a, **k: ("", "SSH command timed out", -1)
    _bc_out = _botcmd._console_text(_bc_app, "rust")
    check("bots: /console on a host that timed out says it couldn't read, not 'isn't running'",
          "isn't running" not in _bc_out and "couldn't read" in _bc_out, _bc_out)
    _bc_game.capture_console = lambda *a, **k: ("NO_SESSION\n", "", 3)
    _bc_out = _botcmd._console_text(_bc_app, "rust")
    check("bots: ...while capture_console's own sentinel still means not running (control)",
          "isn't running" in _bc_out, _bc_out)
    _bc_game.capture_console = lambda *a, **k: ("[chat] Bob: NO_SESSION lol\nServer started\n", "", 0)
    _bc_out = _botcmd._console_text(_bc_app, "rust")
    check("bots: ...and a player SAYING the sentinel word is console output, not a stopped server",
          "isn't running" not in _bc_out and "Server started" in _bc_out, _bc_out)
finally:
    _botcmd._find_server, _bc_game.capture_console = _bc_saved

# ── Discord replies must not be able to ping the channel ──────────────────────────────────────
# The content is not ours: player names (!players), the tail of the live console (which on most
# engines carries in-game chat), package names from a remote host's apt output. Discord parses
# every mention in `content` by default, so a player could pick a name that mass-pings the
# operator's Discord every time an admin ran !players.
from panel.services import notifications as _nt                                    # noqa: E402
_nt_posts = []
_nt_o_post = _nt._post
try:
    _nt._post = lambda url, data=None, headers=None, **k: (
        _nt_posts.append(_json.loads((data or b"{}").decode())), (True, "sent"))[1]
    _nt.send_discord("https://discord.com/api/webhooks/" + "9" * 18 + "/"
                     + "a" * 68, "hello <@everyone>")
    _nt.discord_bot_send("A" * 24 + "." + "B" * 6 + "." + "C" * 38, "9" * 18,
                         "gmodserver — 1 player(s):\n• <@everyone> lol")
finally:
    _nt._post = _nt_o_post
check("discord: every send declares allowed_mentions, so a player name cannot ping the channel",
      len(_nt_posts) == 2 and all(p.get("allowed_mentions") == {"parse": []} for p in _nt_posts),
      str(_nt_posts))
# ...and allowed_mentions stops only pings. Discord still rendered the rest of its markdown in the
# bot's own message, so a player named "[Panel login expired](https://evil.example/login)", or one
# saying "# Re-authenticate at [panel](https://evil.example)" in chat, had the operator's bot post a
# clickable masked link or a headline in the admin channel. Driven through the real dispatcher.
from panel.services.bots import discord as _dcb                                   # noqa: E402
_dcm_sent = []
_dcm_link = "[Panel login expired](https://evil.example/login)"
_dcm_chat = "# Re-authenticate at [panel](https://evil.example)\n```\n# out of the fence"
_dcm_saved = (_nt.discord_bot_send, _botcmd._find_server, _botcmd.player_list,
              _bc_game.capture_console)


def _dcm_fenced(msg, needle):
    """True when `needle` sits inside the message's ONE code block and nothing can close it early."""
    parts = msg.split("```")
    return len(parts) == 3 and needle in parts[1] and needle not in parts[0] + parts[2]


try:
    _nt.discord_bot_send = lambda tok, ch, text: _dcm_sent.append(text)
    _botcmd._find_server = lambda arg: (NS(name="Rust", remote=None, short_name="rustserver",
                                           lgsm_name="rustserver", game_type="rust", port=28015,
                                           query_type=None), None)
    _botcmd.player_list = lambda *a, **k: [{"name": _dcm_link}, {"name": "x`` `y"}]
    _bc_game.capture_console = lambda *a, **k: (_dcm_chat + "\nServer started\n", "", 0)
    _dcb._handle_discord_command(_bc_app, "tok", "9" * 18, "!players rust")
    _dcb._handle_discord_command(_bc_app, "tok", "9" * 18, "!console rust")
    _dcm_players, _dcm_console = (_dcm_sent + ["", ""])[:2]
    check("discord: !players shows a player's name as text, not a masked link",
          _dcm_fenced(_dcm_players, _dcm_link) and "Rust — 2 player(s):" in _dcm_players.split("```")[0],
          _dcm_players)
    check("discord: !console shows chat as text, and a backtick in it cannot close the block",
          _dcm_fenced(_dcm_console, "# Re-authenticate") and "Server started" in _dcm_console.split("```")[1],
          _dcm_console)
    # Control: Telegram sends no parse_mode, so its text stays exactly as it was — the same builder
    # with no fence.
    _dcm_tg = _botcmd._players_text(_bc_app, "rust")
    check("discord: ...while Telegram's /players is plain text as before (control)",
          "```" not in _dcm_tg and ("• " + _dcm_link) in _dcm_tg, _dcm_tg)
finally:
    (_nt.discord_bot_send, _botcmd._find_server, _botcmd.player_list,
     _bc_game.capture_console) = _dcm_saved

# ── A provider that refuses every message must leave a trace ──────────────────────────────────
# _post's HTTPError branch logged nothing and notify()'s sender calls were bare statements, so a
# rotated token or a bot removed from a channel stopped alerting with nothing in the journal,
# nothing in the UI and nothing in the audit log.
import logging as _nt_logging                                                      # noqa: E402
import io as _nt_io                                                                # noqa: E402
_nt_buf = _nt_io.StringIO()
_nt_h = _nt_logging.StreamHandler(_nt_buf)
_nt_log = _nt_logging.getLogger("notifications")
_nt_log.addHandler(_nt_h)
_nt_o_level = _nt_log.level
_nt_log.setLevel(_nt_logging.WARNING)
try:
    import urllib.error as _nt_urlerr                                              # noqa: E402

    # The stub goes on _post's OPENER, not on urllib.request.urlopen: _post stopped using the
    # global opener (it follows redirects off the allow-listed host, carrying Authorization with
    # it). Stubbing urlopen here would intercept nothing and send this fake token to the real
    # api.telegram.org.
    class _RejectingOpener:
        @staticmethod
        def open(req, timeout=None):
            raise _nt_urlerr.HTTPError("https://api.telegram.org/x", 401, "Unauthorized", {}, None)

    _o_open = _nt._OPENER
    _nt._OPENER = _RejectingOpener
    try:
        _nt_res = _nt.send_telegram("1234567890:" + "A" * 35, "12345", "hi")
    finally:
        _nt._OPENER = _o_open
finally:
    _nt_log.removeHandler(_nt_h)
    _nt_log.setLevel(_nt_o_level)
check("notifications: a provider that REJECTS a message says so in the log",
      _nt_res[0] is False and "rejected by telegram" in _nt_buf.getvalue(),
      "%s / %r" % (_nt_res, _nt_buf.getvalue()))

# ── refresh() must report the FETCH, not the cache it read back ───────────────────────────────
# `return bool(serverlist())` reads the cache, which every previous run populated — so this
# answered True with every network fetch failing, and the route turned that into
# {"success": true, "message": "Loaded 30 games."} plus an audit row saying it worked.
from panel.services import lgsm_data as _lg                                        # noqa: E402
_lg_o_fetch = _lg._fetch
try:
    _lg._fetch = lambda name: None                       # every fetch fails
    _lg_bad = _lg.refresh(force=True)
    _lg._fetch = lambda name: ("shortname,gameservername,gamename,os\n"
                               "csgo,csgoserver,CS,ubuntu-24.04\n" if name == _lg.SERVERLIST
                               else "all,bc\n")
    _lg_good = _lg.refresh(force=True)
finally:
    _lg._fetch = _lg_o_fetch
    _lg._mem.clear()
check("lgsm_data: refresh() reports the FETCH, not the cache it read back",
      _lg_bad is False, "returned %r with every fetch failing" % (_lg_bad,))
check("lgsm_data: ...and still reports success when the fetch works", _lg_good is True,
      "returned %r" % (_lg_good,))

# ── "could not read" is not "nobody is playing" ───────────────────────────────────────────────
# console_player_list answered [] for an exception, for rc != 0 (the "not running" case) and for
# empty output, and player_list's `or []` then turned a stopped server into a confirmed-empty one:
# the bot said "no players connected" about a server that was down, and the detail page's
# `unknown` flag — which exists to avoid exactly that wording — never fired.
from panel.ops.ssh_manager import game as _sm_game                                 # noqa: E402
_pl_o_send, _pl_o_cap = _sm_game._core.send_console_command, _sm_game.capture_console
try:
    _sm_game._core.send_console_command = lambda *a, **k: ("", "", 0)
    _sm_game.capture_console = lambda *a, **k: ("NO_SESSION", "", 3)
    check("players: a stopped server reads as UNKNOWN, not as empty",
          _sm_game.console_player_list(None, "u", "cod", selfname="codserver") is None)
    check("players: ...and player_list passes that through instead of an empty list",
          _sm_game.player_list(None, "u", "cod", 28960, None, "codserver",
                               allow_console=True) is None)
    _sm_game.capture_console = lambda *a, **k: (
        "num score ping guid   name            lastmsg address               qport rate\n", "", 0)
    check("players: a table that really is empty still reads as empty",
          _sm_game.player_list(None, "u", "cod", 28960, None, "codserver",
                               allow_console=True) == [])
    # ── and the SEND has to have landed, not just the capture ─────────────────────────────────
    # The send's (out, err, rc) was thrown away. On the tailscale and local transports a failed
    # send does NOT raise — _run_via_ssh_cli returns ("", "SSH command timed out", -1) — so the
    # except never saw it, while the capture is a separate round trip 0.8s later that succeeds
    # happily. What came back was the pane's PREVIOUS `status` table, returned as the current
    # player list: players who had already left, with their SteamIDs, on rows whose Ban fans out
    # fleet-wide and into GlobalBan.
    _STALE_TABLE = ('hostname: old\nversion : 1\n'
                    '# userid name uniqueid connected ping loss state\n'
                    '# 2 "Ghost" STEAM_0:1:5 01:02 40 0 active\n')
    _sm_game.capture_console = lambda *a, **k: (_STALE_TABLE, "", 0)
    _sm_game._core.send_console_command = lambda *a, **k: ("", "SSH command timed out", -1)
    _stale = _sm_game.console_player_list(None, "u", "gmod", selfname="gmodserver")
    check("players: a `status` that was never delivered does not read the pane's old table",
          _stale is None,
          "answered %r — that is the previous reply, presented as the current one" % (_stale,))
    _stale_cs = _sm_game.console_status(None, "u", "gmod", selfname="gmodserver")
    check("players: ...and console_status says unknown too, rather than ([], None)",
          _stale_cs == (None, None), str(_stale_cs))
    # Positive control: with the send accepted, the very same pane still parses.
    _sm_game._core.send_console_command = lambda *a, **k: ("", "", 0)
    _live = _sm_game.console_player_list(None, "u", "gmod", selfname="gmodserver")
    check("players: ...while a delivered `status` still parses that table",
          [p["name"] for p in (_live or [])] == ["Ghost"], str(_live))
finally:
    _sm_game._core.send_console_command, _sm_game.capture_console = _pl_o_send, _pl_o_cap

# ── `$` vs `\Z`: every compiled pattern is classified, and the validators are RUN ─────────────
# `$` matches before a trailing newline and `\Z` does not. On a pattern that decides whether a
# value may reach a URL path, an Authorization header, a crontab line or a privileged verb, that is
# the difference between refusing "x\n" and accepting it. On a pattern that parses ONE LINE of
# command output — `(.*)$`, `(.+)$`, `\s*$` — the two are not interchangeable: `\Z` would refuse the
# line's own newline and break it.
#
# So this is not a sweep. Every module-level `re.compile` whose pattern ends in `$` has to appear in
# one of the two lists below, and a new one fails this gate until somebody has decided which it is.
# The validators are then EXECUTED against "<valid sample>\n".
import ast as _anc_ast                                                             # noqa: E402
import glob as _anc_glob                                                           # noqa: E402

# Line parsers: `$` is correct because the pattern is matched against one line and the trailing
# whitespace/newline is either absorbed by the pattern or captured on purpose.
_ANCHOR_LINE_PARSERS = {
    "_CRON_VERDICT_RE", "_CFG_LINE_RE", "_MOD_AVAIL_RE", "_MOD_INST_RE", "_HOSTNAME_RE",
    "_UFW_RULE_RE", "_CONSOLE_PROMPT_RE", "_ASCII_INT_RE", "header",
    # One crontab line, already .strip()ed by its only caller, and its own `\s*$` absorbs
    # whatever is left — so $ and \Z behave identically here.
    "_CRON_WRAP_RE",
}
# Validators: the value goes somewhere a newline would matter. Each maps to a sample that must be
# ACCEPTED, so the gate cannot be satisfied by a pattern that refuses everything.
_ANCHOR_VALIDATORS = {
    "panel.services.notifications": {
        "_DISCORD_WEBHOOK_RE": "https://discord.com/api/webhooks/123456789012345/" + "a" * 68,
        "_TG_TOKEN_RE": "1234567890:" + "A" * 35,
        "_DISCORD_BOT_TOKEN_RE": "A" * 24 + "." + "B" * 6 + "." + "C" * 38,
        # Built, not written: an 18-digit literal is a Discord snowflake by shape and
        # gitleaks' discord-client-id rule is right to say so. Same reason as its
        # neighbours here, which are also assembled.
        "_DISCORD_CHANNEL_RE": "9" * 18,
        "_NTFY_TOPIC_RE": "panel-alerts",
        "_NTFY_URL_RE": "https://ntfy.sh/panel-alerts",
    },
    "panel.ops.system_ops": {"_JAIL_RE": "sshd"},
    "panel.ops.ssh_manager.gmod": {"_DF_PATH_RE": "/home/gmodserver"},
    "panel.ops.ssh_manager.files": {"_MOD_ID_OK": "metamodsource"},
    "panel.db.prefs": {"_PANEL_KEY_RE": "host-tile"},
    "panel.ops.ssh_manager.cron": {"_SIMPLE_CMD_RE": "/home/gs/gsserver monitor"},
    "panel.ops.ssh_manager.hosts": {"_UFW_PORT_SPEC_RE": "27015:27020"},
    "panel.core.clock": {"_HHMM_RE": "05:30"},
}

import importlib as _anc_il                                                        # noqa: E402
_anc_bad = []
for _mod_name, _pats in _ANCHOR_VALIDATORS.items():
    _mod = _anc_il.import_module(_mod_name)
    for _name, _sample in _pats.items():
        _rx = getattr(_mod, _name, None)
        if _rx is None:
            _anc_bad.append("%s.%s is gone" % (_mod_name, _name))
            continue
        if not _rx.match(_sample):
            _anc_bad.append("%s refuses its own valid sample %r" % (_name, _sample))
        if _rx.match(_sample + "\n"):
            _anc_bad.append("%s accepts a trailing newline" % _name)
check("regex anchors: every validator refuses a trailing newline (\\Z, not $)", not _anc_bad,
      "; ".join(_anc_bad[:4]))

# ...and nothing new slips in unclassified.
_anc_known = set(_ANCHOR_LINE_PARSERS)
for _p in _ANCHOR_VALIDATORS.values():
    _anc_known |= set(_p)
_anc_unclassified = []
for _f in sorted(_anc_glob.glob(os.path.join(_root, "panel", "**", "*.py"), recursive=True)
                 + [os.path.join(_root, n) for n in ("app.py", "manage.py", "db_maintenance.py")]):
    try:
        _tree = _anc_ast.parse(open(_f, encoding="utf-8").read())
    except SyntaxError:
        continue
    for _n in _anc_ast.walk(_tree):
        if not (isinstance(_n, _anc_ast.Assign) and isinstance(_n.value, _anc_ast.Call)
                and getattr(_n.value.func, "attr", "") == "compile" and _n.value.args):
            continue
        _parts = [a.value for a in _n.value.args[:1] + getattr(_n.value.args[0], "values", [])
                  if isinstance(a, _anc_ast.Constant) and isinstance(a.value, str)]
        _pat = "".join(_parts) if _parts else ""
        if not _pat or not _pat.endswith("$") or _pat.endswith("\\$"):
            continue
        for _t in _n.targets:
            if isinstance(_t, _anc_ast.Name) and _t.id not in _anc_known:
                _anc_unclassified.append("%s:%d %s" % (os.path.basename(_f), _n.lineno, _t.id))
check("regex anchors: every $-anchored pattern is classified as a validator or a line parser",
      not _anc_unclassified,
      "unclassified (decide, then add to the list in this test): %s" % _anc_unclassified[:5])

# ── the same question for an INLINE re.match/fullmatch/search ─────────────────────────────────
# The sweep above walks module-level `X = re.compile(...)` assignments, which is a shape an
# inline `re.match(r"^...$", value)` does not have — so it could not see notifications.py's ntfy
# token check, which said in its own comment that it was there so "a pasted value carrying a
# newline can never split the header" and then used `$`, the one anchor that matches before a
# trailing newline. Exactly the class the sweep exists to prevent, in the blind spot it left.
# Listed rather than banned: an inline `$` is fine in a LINE parser (the string being matched is
# already one line); what must not happen is a new one appearing without somebody deciding which
# it is.
# Keyed on the PATTERN, not on a line number, so moving the code does not silently re-allow it.
# Each of these is handed one line that has already been split off, so there is no trailing
# newline for `$` to be lenient about — which is the whole difference between a line parser and a
# validator. The six that were VALIDATORS by that test now use \\Z: two IP-shape checks on values
# read off a remote host, a LinuxGSM config key, a .cfg filename going into `find`, an apt package
# name, and a mod id.
_INLINE_DOLLAR_OK = {
    r"\)\s+CMD\s+\((.*)\)\s*$",                                  # a syslog cron line
    r"^#{3,}\s+(.+?)\s+#{3,}\s*$",                                 # a config section header
    r"^(.*)/(tcp|udp)$",                                            # a ufw port column
    r"^\s*\[\s*(\d+)\]\s*(.*)$",                                   # a `ufw status numbered` row
    r"\s*(\d+)\s+(-?\d+)\s+(\d+)\s+([0-9A-Fa-f]{6,})\s+(.+)$",      # an idTech3 player row
    r"^\s*([a-z][a-z0-9-]*)\s+([a-z]{1,4})\s+\|\s+(.+?)\s*$",        # a LinuxGSM table row
    r"github\.com[/:]([^/]+/[^/]+?)(?:\.git)?/?\s*$",                # a `git remote -v` line
    r"\s*port\s*=\s*(\d+)\s*$",                                     # an sshd_config line
    r"^(https?://\S+)\s*(\(.*\))?$",                                # a `tailscale up` output line
}
_inline_bad = []
for _f in sorted(_anc_glob.glob(os.path.join(_root, "panel", "**", "*.py"), recursive=True)
                 + [os.path.join(_root, n) for n in ("app.py", "manage.py", "db_maintenance.py")]):
    _rel = os.path.relpath(_f, _root)
    try:
        _tree = _anc_ast.parse(open(_f, encoding="utf-8").read())
    except SyntaxError:
        continue
    for _n in _anc_ast.walk(_tree):
        if not (isinstance(_n, _anc_ast.Call)
                and getattr(_n.func, "attr", "") in ("match", "fullmatch", "search")
                and getattr(getattr(_n.func, "value", None), "id", "") == "re"
                and _n.args and isinstance(_n.args[0], _anc_ast.Constant)
                and isinstance(_n.args[0].value, str)):
            continue
        _pat = _n.args[0].value
        if not _pat.endswith("$") or _pat.endswith("\\$"):
            continue
        if _pat not in _INLINE_DOLLAR_OK:
            _inline_bad.append("%s:%d %r" % (_rel, _n.lineno, _pat[:44]))
check("regex anchors: no unclassified $-anchored inline re.match/search either",
      not _inline_bad,
      "use \\Z for a VALIDATOR, or add the file to _INLINE_DOLLAR_OK saying why $ is right: %s"
      % _inline_bad[:5])

# ── A no-op UPDATE must still refresh what lives outside the checkout ─────────────────────────
# "Nothing to fetch" is not "nothing to do". The helper, db_maintenance.py and the sudoers grant
# live outside PANEL_DIR, so they can be stale or missing while the code is perfectly current —
# and this branch used to `exit 0` before reaching any of them. Two consequences, both measured:
# the remedy install.sh itself prints ("re-run this installer as root…") did nothing on a host
# whose code was current, and a host that took new code by another route (the panel's own
# self-update, or a git pull) kept an old helper and an old grant — so new verbs answered
# "unknown verb" and the game-user grant was never written, while the run reported success.
_noop_i = _inst.find('[ "${CURRENT_SHA}" = "${TARGET_SHA}" ]')
_noop_j = _inst.find("Already up to date", _noop_i) if _noop_i != -1 else -1
check("install.sh: the no-op update branch is where this gate expects it",
      _noop_i != -1 and _noop_j > _noop_i, "start=%d end=%d" % (_noop_i, _noop_j))
_noop = _inst[_noop_i:_noop_j] if (_noop_i != -1 and _noop_j > _noop_i) else ""
for _needed in ("install_root_tools", "write_sudoers_grant", "check_origin_trusted"):
    check("install.sh: a no-op update still runs %s" % _needed,
          _needed in _noop, "missing from the up-to-date branch")
# ...and it must still be gated on the origin, exactly as the real update path is: an untrusted
# origin must not be able to get a grant written for it by doing nothing.
check("install.sh: ...with the grant still gated on a trusted origin",
      '[ "${ORIGIN_TRUSTED}" -eq 1 ] && write_sudoers_grant' in _noop, _noop[-200:])

# ── no unit check may READ or WRITE the machine's own config.json ──────────────────────────────
# Two turned up in one audit. part06's PrefixMiddleware checks READ it, so they passed on a dev box
# and failed four ways on any host with a Tailscale mount. part03's round-trip WROTE to it — the
# live config of a running panel — restoring the text in a finally that a kill would skip, and
# leaving a stray `_roundtrip_probe` behind entirely on a machine that had no config.json to
# restore. Both are the same defect: a unit test that means different things on different machines,
# and the machines it goes wrong on are the real installs.
#
# The rule: touch config through a redirected CONFIG_FILE or a stubbed load_config, never the
# module's own path. Checked per FILE, because the redirect and the use are rarely adjacent.
_cfg_guard = []
for _f in sorted(os.listdir(os.path.join(_root, "tests", "unit"))):
    if not _f.endswith(".py"):
        continue
    _src = open(os.path.join(_root, "tests", "unit", _f), encoding="utf-8").read()
    _uses = sum(1 for _n in _ast.walk(_ast.parse(_src))
                if isinstance(_n, _ast.Call)
                and getattr(_n.func, "attr", getattr(_n.func, "id", "")) in
                ("load_config", "save_config"))
    if not _uses:
        continue
    _redirects = ("CONFIG_FILE =" in _src or ".CONFIG_FILE=" in _src
                  or "load_config =" in _src)
    if not _redirects:
        _cfg_guard.append("%s (%d call(s), no redirect)" % (_f, _uses))
check("suites: no unit file reads or writes the machine's own config.json",
      not _cfg_guard, "; ".join(_cfg_guard))

# ── the deploy must ASK where the panel is, not assume it ────────────────────────────────────
# install.sh has supported two service models since 2026-07-04: a per-user install under the
# invoking user's home, and a ROOT install that runs as the dedicated 'lgsmpanel' service user out
# of ITS home. deploy.yml hardcoded the first — `cd ~/linuxgsm-panel` — so the day a host was
# converted to the hardened root model the deploy broke on every single run, 62 times over three
# days, on a `cd:` error that says nothing about why.
#
# Read as TEXT like the fuzz-workflow gate above — the shell lives inside a YAML block scalar, so
# what matters is the literal string that ends up on the host — but with the COMMENT LINES
# STRIPPED FIRST. The first version of this block did not, and failed immediately on the sentence
# two paragraphs up that quotes `cd ~/linuxgsm-panel` while explaining why it is wrong. That cuts
# both ways and the other way is worse: without stripping, a comment mentioning
# `systemctl show -p WorkingDirectory` would satisfy the positive checks below while the script
# did nothing of the kind. Lines whose first non-space character is '#' only — enough for a
# workflow file, and it never has to parse YAML to be right about this.
_deploy_raw = open(os.path.join(_root, ".github", "workflows", "deploy.yml"),
                   encoding="utf-8").read()
_deploy_wf = "\n".join(_ln for _ln in _deploy_raw.splitlines()
                        if not _ln.lstrip().startswith("#"))
check("deploy: the workflow does not hardcode the per-user panel path",
      "cd ~/linuxgsm-panel" not in _deploy_wf,
      "`cd ~/linuxgsm-panel` is back — that assumes the per-user layout and fails on every "
      "root-install host, which is the model install.sh creates when run with sudo")
check("deploy: ...it asks the unit where the panel lives instead",
      "systemctl show -p WorkingDirectory" in _deploy_wf,
      "nothing derives the install directory from the host")
check("deploy: ...and still handles a per-user install",
      "${HOME}/linuxgsm-panel" in _deploy_wf,
      "the fallback branch for a per-user install is gone, so those hosts stop deploying")
# The service user's home is 0750, so the deploy account cannot stat the checkout: every read of
# it has to go through sudo, and the git work has to run as the OWNER (root on a repo it does not
# own trips git's safe.directory). Both were found only by running it against a real host.
check("deploy: ...reads the system install through sudo",
      "sudo -n test -d" in _deploy_wf and "sudo -n stat -c %U" in _deploy_wf,
      "a plain [ -d ] / stat on the service user's home is false-y for the deploy user, and the "
      "script silently takes the wrong branch")
# ...and ROOT EXECUTES NOTHING OUT OF THAT CHECKOUT. The system branch used to refresh
# ${PD}/install.sh with `git checkout` as the service user and then run it with `sudo bash`, so on
# every green merge root ran bytes from a tree AND a .git that the account the helper boundary
# contains owns outright. Run the job's real `run:` block with ssh capturing what it sends, then run
# THAT on a shimmed "host" (sudo/systemctl/git): record what root would execute, and what the file
# held at the moment it ran.
_dp_run = _deploy_raw[_deploy_raw.index("        run: |\n") + len("        run: |\n"):]
_dp_run = "\n".join(_ln[10:] if _ln.startswith(" " * 10) else _ln
                    for _ln in _dp_run.splitlines()) + "\n"
_dp_sb = _tempfile.mkdtemp(prefix="deploy-")
try:
    _dp_pd = os.path.join(_dp_sb, "lgsmpanel", "linuxgsm-panel")
    os.makedirs(_dp_pd)
    with open(os.path.join(_dp_pd, "install.sh"), "w") as _dp_f:
        _dp_f.write("#!/bin/bash\necho PANEL-OWNED-INSTALLER\n")
    _dp_log = os.path.join(_dp_sb, "log")
    _dp_shipped = "#!/bin/bash\necho SHIPPED-INSTALLER\n"
    _dp_shims = (
        'LOG=%s\n' % _shlex_q(_dp_log)
        + 'systemctl() { echo %s; }\n' % _shlex_q(_dp_pd)
        + 'git() { echo "GIT $*" >> "$LOG"; }\n'
        # sudo: file plumbing runs for real (unprivileged); anything that would EXECUTE as root is
        # recorded together with the bytes it would have run.
        + 'sudo() {\n'
          '  [ "$1" = -n ] && shift\n'
          '  case "$1" in\n'
          '    test|stat|mktemp|tee|rm) "$@" ;;\n'
          '    -u) echo "AS-USER $*" >> "$LOG" ;;\n'
          '    env) shift; while [ "${1#*=}" != "$1" ]; do echo "ROOT-ENV $1" >> "$LOG"; shift; done\n'
          '         echo "ROOT-EXEC $*" >> "$LOG"\n'
          '         [ "$1" = bash ] && echo "ROOT-BYTES $(cat "$2")" >> "$LOG" ;;\n'
          '    *) echo "ROOT-EXEC $*" >> "$LOG" ;;\n'
          '  esac\n'
          '}\n')
    # The runner: its checkout holds the verified commit's install.sh; ssh just records the stream.
    _dp_runner = os.path.join(_dp_sb, "runner")
    os.makedirs(_dp_runner)
    with open(os.path.join(_dp_runner, "install.sh"), "w") as _dp_f:
        _dp_f.write(_dp_shipped)
    _dp_stream = os.path.join(_dp_sb, "stream")
    _dp_sha = ("0123456789abcdef" * 3)[:40]
    _dp_rr = _sh_sub.run(["bash", "-c", 'ssh() { cat > %s; }\n' % _shlex_q(_dp_stream) + _dp_run],
                         capture_output=True, text=True, cwd=_dp_runner,
                         env=dict(os.environ, DEPLOY_HOST="host.invalid", DEPLOY_USER="ubuntu",
                                  HEAD_SHA=_dp_sha))
    _dp_sent = open(_dp_stream).read() if os.path.exists(_dp_stream) else ""
    _dp_r = _sh_sub.run(["bash", "-c", _dp_shims + _dp_sent], capture_output=True, text=True,
                        cwd=_dp_sb, env=dict(os.environ, HOME=_dp_sb))
    _dp_got = open(_dp_log).read() if os.path.exists(_dp_log) else ""
    _dp_exec = [ln for ln in _dp_got.splitlines() if ln.startswith("ROOT-EXEC ")]
    check("deploy: the system branch is taken for a unit-reported checkout (positive control)",
          "System install at %s" % _dp_pd in _dp_r.stdout and _dp_exec,
          "runner rc=%s err=%r; host rc=%s out=%r err=%r log=%r" % (
              _dp_rr.returncode, _dp_rr.stderr[-200:], _dp_r.returncode, _dp_r.stdout[-200:],
              _dp_r.stderr[-300:], _dp_got[-300:]))
    check("deploy: ...and root executes nothing from the service user's checkout",
          _dp_exec and not any(_dp_pd in ln for ln in _dp_exec)
          and "PANEL-OWNED-INSTALLER" not in _dp_got,
          _dp_got[-400:])
    check("deploy: ...it runs the installer the job shipped, byte for byte",
          "ROOT-BYTES " + _dp_shipped.strip() in _dp_got,
          _dp_got[-400:])
    check("deploy: ...and nothing touches that checkout's git on root's behalf",
          "GIT " not in _dp_got and "AS-USER" not in _dp_got, _dp_got[-400:])
    # ...pinned to the commit whose installer it shipped. Left to reset to origin/main's tip, this
    # commit's installer installed a newer push's code, and that push's own deploy then found the
    # host current and never ran its update steps.
    check("deploy: ...and pins the code to the commit whose installer it shipped",
          "ROOT-ENV PANEL_UPDATE_REF=%s" % _dp_sha in _dp_got.splitlines(), _dp_got[-400:])
    # The id is spliced into the remote script, so anything but a commit id stops the job there.
    _dp_bad = os.path.join(_dp_sb, "stream-bad")
    _dp_rb = _sh_sub.run(["bash", "-c", 'ssh() { cat > %s; }\n' % _shlex_q(_dp_bad) + _dp_run],
                         capture_output=True, text=True, cwd=_dp_runner,
                         env=dict(os.environ, DEPLOY_HOST="host.invalid", DEPLOY_USER="ubuntu",
                                  HEAD_SHA=_dp_sha[:39] + "\ntouch /tmp/x"))
    check("deploy: ...and refuses a head_sha that is not a commit id, sending nothing",
          _dp_rb.returncode != 0 and not os.path.exists(_dp_bad), _dp_rb.stderr[-200:])
finally:
    _shutil.rmtree(_dp_sb, ignore_errors=True)

# install.sh honours that pin only as an UPDATE: a pinned commit the checkout already contains
# leaves it where it is. Deploy runs do not finish in push order — a re-run of an old commit's CI
# deploys it last — and resetting to the pin would take the host backwards. Run the real
# resolve_update_target against a real clone.
_ru_fn = (_inst[_inst.index("_gitc() {"):_inst.index("\n}\n", _inst.index("_gitc() {")) + 3]
          + _inst[_inst.index("resolve_update_target() {"):
                  _inst.index("\n}\n", _inst.index("resolve_update_target() {")) + 3])
_ru_sb = _tempfile.mkdtemp(prefix="updref-")
try:
    _ru_up, _ru_co = os.path.join(_ru_sb, "up"), os.path.join(_ru_sb, "co")

    def _ru_git(*a):
        return _sh_sub.run(["git", *a], capture_output=True, text=True).stdout.strip()

    _ru_git("init", "-q", "-b", "main", _ru_up)
    _ru_c = []
    for _n in ("A", "B", "C"):
        _ru_git("-C", _ru_up, "-c", "user.email=t@example.invalid", "-c", "user.name=t",
                "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", _n)
        _ru_c.append(_ru_git("-C", _ru_up, "rev-parse", "HEAD"))
    _ru_git("clone", "-q", _ru_up, _ru_co)

    def _ru_target(head, ref):
        _ru_git("-C", _ru_co, "reset", "-q", "--hard", head)
        r = _sh_sub.run(["bash", "-c", "SRC=''\nPANEL_DIR=%s\nDEFAULT_BRANCH=main\n%s"
                         "resolve_update_target\necho \"TARGET=${TARGET_SHA}\""
                         % (_shlex_q(_ru_co), _ru_fn)],
                        capture_output=True, text=True,
                        env=dict(os.environ, PANEL_UPDATE_REF=ref))
        return r.stdout.strip().rpartition("TARGET=")[2] or r.stderr[-200:]

    _ru_a, _ru_b, _ru_cc = _ru_c
    check("install.sh: a pinned update ref ahead of the checkout is the target (positive control)",
          _ru_target(_ru_a, _ru_b) == _ru_b, _ru_target(_ru_a, _ru_b))
    check("install.sh: ...with no pin, the target is the branch tip (positive control)",
          _ru_target(_ru_a, "") == _ru_cc, _ru_target(_ru_a, ""))
    check("install.sh: a pinned ref the checkout already contains never moves it backwards",
          _ru_target(_ru_cc, _ru_a) == _ru_cc, _ru_target(_ru_cc, _ru_a))
    # ...but a checkout carrying a commit upstream does not have is still reset to the pin, as it
    # was before: "never backwards" is about newer UPSTREAM commits only.
    _ru_git("-C", _ru_co, "reset", "-q", "--hard", _ru_cc)
    _ru_git("-C", _ru_co, "-c", "user.email=t@example.invalid", "-c", "user.name=t",
            "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "local")
    _ru_local = _ru_git("-C", _ru_co, "rev-parse", "HEAD")
    check("install.sh: ...while a local commit on top is still reset to the pin",
          _ru_target(_ru_local, _ru_a) == _ru_a, _ru_target(_ru_local, _ru_a))
finally:
    _shutil.rmtree(_ru_sb, ignore_errors=True)

# ── the admin's 2FA reset must be VISIBLE, not just present ──────────────────────────────────
# The switch lives in the Edit User modal and used to sit in a `display:none` block that JS
# revealed only for an account that already had 2FA on. Correct, and undiscoverable: an admin
# opening the dialog to reset someone's second factor saw an empty section and no way to tell an
# inapplicable feature from an absent one. It is rendered disabled with a reason instead.
#
# Matched INSIDE the tag (`id="eu-2fa-block" ... display:none`), not anywhere in the file — the
# comment above that div explains the old behaviour and would satisfy a looser search. Same trap
# the deploy gate hit.
_mu_html = open(os.path.join(_root, "templates", "manage_users.html"), encoding="utf-8").read()
check("users page: the 2FA reset control is not hidden at render time",
      not re.search(r'id="eu-2fa-block"[^>]*display\s*:\s*none', _mu_html),
      "the block is display:none again — an admin looking for the 2FA reset finds nothing")
_mu_js = open(os.path.join(_root, "static", "js", "manage_users.js"), encoding="utf-8").read()
check("users page: ...and the script disables it rather than hiding it",
      "box.disabled = !u.totp_enabled" in _mu_js,
      "nothing marks the switch inert for an account with no 2FA, so it would post a no-op")
# The superadmin switch is rendered only for a superadmin (add_user refuses the grant from anyone
# else and loses the whole form doing it), so the populate step must survive its absence. An
# unguarded `getElementById('eu-superadmin').checked` throws, and EVERYTHING after it in that
# function — the active switch, the 2FA reset, the password reset, and the modal's own .show() —
# never runs: the Edit dialog would simply not open for a delegated user admin.
check("users page: the edit dialog survives the superadmin switch not being rendered",
      re.search(r"getElementById\('eu-superadmin'\)\s*;", _mu_js) is not None
      and "if (euSuper)" in _mu_js,
      "the lookup is dereferenced unguarded, so removing the control breaks the whole dialog")

# ── exactly ONE handler per socket event ──────────────────────────────────────────────────────
# flask-socketio does not chain handlers. python-socketio's BaseServer.on ends in
# `self.handlers[namespace][event] = handler`, so a second @socketio.on("disconnect") REPLACES the
# first and the first never runs again — no warning, no error, and nothing in the app's own tests
# noticed.
#
# It happened: the host terminal added its own disconnect handler and deleted the console's viewer
# cleanup. A browser that closed would have stayed in _console_viewers forever, with the poller
# still SSH-ing `stat -c%s` at the host on its behalf, for every console ever opened. Caught by
# reading the library, not by the suite, which is why this check exists.
#
# Parsed, not grepped. The first version of this gate searched the source text and failed on the
# comment you are reading — the same way the deploy gate matched `cd ~/linuxgsm-panel` quoted in
# its own explanation. A decorator is an AST node; prose is not.
import ast as _ast6

_sock_handlers = {}          # event -> [(relpath, funcname), ...]
_sock_fns = {}               # (relpath, event) -> the FunctionDef node
for _sf in sorted(glob.glob(os.path.join(_root, "panel", "**", "*.py"), recursive=True)):
    _rel6 = os.path.relpath(_sf, _root)
    for _node in _ast6.walk(_ast6.parse(open(_sf, encoding="utf-8").read())):
        if not isinstance(_node, (_ast6.FunctionDef, _ast6.AsyncFunctionDef)):
            continue
        for _dec in _node.decorator_list:
            if not (isinstance(_dec, _ast6.Call) and isinstance(_dec.func, _ast6.Attribute)
                    and _dec.func.attr == "on"
                    and isinstance(_dec.func.value, _ast6.Name)
                    and _dec.func.value.id == "socketio"):
                continue
            if _dec.args and isinstance(_dec.args[0], _ast6.Constant) \
                    and isinstance(_dec.args[0].value, str):
                _ev = _dec.args[0].value
                _sock_handlers.setdefault(_ev, []).append((_rel6, _node.name))
                _sock_fns[(_rel6, _ev)] = _node

_dupe_ev = {k: v for k, v in _sock_handlers.items() if len(v) > 1}
check("socket: no event has two handlers (the second would silently replace the first)",
      not _dupe_ev,
      "registered twice: " + "; ".join(
          f"{k} -> " + ", ".join(f"{fn}() in {f}" for f, fn in v) for k, v in _dupe_ev.items())
      + " — flask-socketio keeps one handler per event, so the earlier one is now dead code")
check("socket: the app has a disconnect handler at all",
      "disconnect" in _sock_handlers,
      "nothing cleans up per-socket state when a browser goes away")

# ...and that the one handler still runs everyone's cleanup, not just its own.
_disc_where = _sock_handlers.get("disconnect", [(None, None)])[0]
_disc_fn = _sock_fns.get((_disc_where[0], "disconnect"))
check("socket: the disconnect handler runs the registered hooks",
      _disc_fn is not None and any(
          isinstance(n, _ast6.Call) and getattr(n.func, "attr", getattr(n.func, "id", None))
          == "run_disconnect_hooks" for n in _ast6.walk(_disc_fn)),
      f"the sole disconnect handler ({_disc_where[1]} in {_disc_where[0]}) does not call "
      "socket_hooks, so the terminal never tears its shell down when a browser closes")
check("socket: the terminal does not register a disconnect handler of its own",
      not any(f == "panel/routes/host_terminal.py" for f, _ in _sock_handlers.get("disconnect", [])),
      "the terminal registered a disconnect handler again — that deletes the console's")
_tsrc6 = _modsrc("panel/routes/host_terminal.py")
check("socket: ...it registers a hook instead",
      any(isinstance(n, _ast6.Call)
          and getattr(n.func, "attr", getattr(n.func, "id", None)) == "add_disconnect_hook"
          for n in _ast6.walk(_ast6.parse(_tsrc6))),
      "nothing tears the shell down when a browser closes without sending term_close")

# One hook raising must not skip the hooks after it: a leaked shell is no reason to leak a console
# viewer too.
import importlib as _il6
_hooks_mod = _il6.import_module("panel.ops.socket_hooks")
_seen6 = []
_hooks_mod.add_disconnect_hook(lambda sid: (_ for _ in ()).throw(RuntimeError("boom")))
def _second_hook(sid): _seen6.append(sid)
_hooks_mod.add_disconnect_hook(_second_hook)
_hooks_mod.run_disconnect_hooks("sid-1")
check("socket: a hook that raises does not stop the ones after it", _seen6 == ["sid-1"],
      f"the second hook did not run: {_seen6}")
_hooks_mod.add_disconnect_hook(_second_hook)          # same function, registered twice
_seen6.clear()
_hooks_mod.run_disconnect_hooks("sid-2")
check("socket: registering the same hook twice does not run it twice", _seen6 == ["sid-2"],
      f"ran {len(_seen6)} times: {_seen6}")

# ── a closed browser must take the shell with it, even when SIGHUP is ignored ─────────────────
# The teardown sent one SIGHUP to the process group and moved on. An ignored signal disposition
# survives fork AND execve, so when the panel process itself ignores SIGHUP — which is what
# `nohup` does, and what anything started from such a shell inherits — killpg reported success
# having done nothing, and every closed browser tab left an `ssh -tt` to the remote host running
# for good. Found on the real VPS: the ssh was still there minutes after the socket dropped, and
# /proc/<pid>/status showed SigIgn bit 0 set on both the panel and the ssh.
#
# The child here ignores SIGHUP *and* SIGTERM, so nothing short of the full escalation ends it.
import logging as _lg6
import pty as _pty6
import subprocess as _sp6
import threading as _th6

_tsmod = _il6.import_module("panel.ops.terminal_session")
_stubborn = ("import signal, sys, time\n"
             "signal.signal(signal.SIGHUP, signal.SIG_IGN)\n"
             "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
             "sys.stdout.write('ready\\n'); sys.stdout.flush()\n"
             "time.sleep(120)\n")
_m6, _s6 = _pty6.openpty()
_proc6 = _sp6.Popen([sys.executable, "-c", _stubborn], stdin=_s6, stdout=_s6, stderr=_s6,
                    start_new_session=True)
os.close(_s6)
_sess6 = _tsmod.Session("unit-sid", "unit", lambda sid, d: None, lambda sid, r: None)
_sess6._fd = _m6
_sess6._proc = _proc6
# Wait for the child to SAY it has installed the handlers, rather than sleeping and hoping — a
# race here would make this test pass for the wrong reason on a loaded machine.
import select as _sel6
_ready6, _t0_6 = b"", _time.time()
while b"ready" not in _ready6 and _time.time() - _t0_6 < 10:
    if _sel6.select([_m6], [], [], 0.2)[0]:
        _ready6 += os.read(_m6, 1024)
check("terminal: the stubborn child announced itself (the next checks are not vacuous)",
      b"ready" in _ready6, "child never printed ready: %r" % (_ready6,))
_sess6._pump = _th6.Thread(target=_tsmod._pump_fd, args=(_sess6,), daemon=True, name="unit-pump")
_sess6._pump.start()

# Capture what the teardown logs: if the pump had to be overruled it says so, and that is the
# descriptor race this ordering exists to avoid.
class _Cap6(_lg6.Handler):
    def __init__(self): _lg6.Handler.__init__(self); self.msgs = []
    def emit(self, rec): self.msgs.append(rec.getMessage())


_cap6 = _Cap6()
_lg6.getLogger("panel.terminal").addHandler(_cap6)
# WHICH thread closes the pty master is the whole point, so record it. Asserting only that the fd
# ends up None cannot tell the two apart: the caller closing it early also sets None, and that
# version of this check passed against the very bug it was written for.
_closed_by6 = []
_real_close6 = os.close


def _spy_close6(fd):
    if fd == _m6:
        _closed_by6.append(_th6.current_thread().name)
    return _real_close6(fd)


os.close = _spy_close6
try:
    _sess6.close("unit test")
finally:
    os.close = _real_close6
    _lg6.getLogger("panel.terminal").removeHandler(_cap6)
_t0_6 = _time.time()
while _proc6.poll() is None and _time.time() - _t0_6 < 5:
    _time.sleep(0.05)
check("terminal: close() kills a child that ignores SIGHUP and SIGTERM",
      _proc6.poll() is not None,
      "the process outlived close() — a closed browser tab leaks an ssh to the remote host, one "
      "more every time anyone opens a terminal")
check("terminal: ...and does not report success without checking",
      not any("survived SIGKILL" in m for m in _cap6.msgs),
      "teardown logged that the process outlived SIGKILL: %r" % (_cap6.msgs,))
check("terminal: the pump closes its own descriptor (idle pump)",
      _closed_by6[:1] == ["unit-pump"],
      "the pty master was closed by %r while the pump thread was still select()ing on it — that "
      "descriptor number is immediately reusable, so the pump can wake on another session's "
      "socket and write its bytes into this browser (log: %r)" % (_closed_by6, _cap6.msgs))
check("terminal: ...and exactly once",
      len(_closed_by6) == 1,
      "the pty master was closed %d times (%r) — a second close can land on a descriptor number "
      "something else has already been given" % (len(_closed_by6), _closed_by6))
if _proc6.poll() is None:
    _proc6.kill()


# ── ...and when the pump is BUSY, which is the case the join exists for ───────────────────────
# The check above passes with the join deleted: an idle pump is already out of select() by the
# time the caller gets to the descriptor, so it wins the race on its own. The case that matters is
# a pump stuck inside _emit — socketio.emit to a browser that has stopped reading — because that
# is when the caller would close a descriptor the pump is about to use again. So block the pump on
# an event the test controls and release it mid-teardown.
_gate6 = _th6.Event()
_in_emit6 = _th6.Event()


def _slow_out6(sid, data):
    _in_emit6.set()
    _gate6.wait(timeout=10)


_chatty6 = ("import sys, time\n"
            "while True:\n"
            "    sys.stdout.write('x' * 64 + '\\n'); sys.stdout.flush(); time.sleep(0.02)\n")
_m7, _s7 = _pty6.openpty()
_proc7 = _sp6.Popen([sys.executable, "-c", _chatty6], stdin=_s7, stdout=_s7, stderr=_s7,
                    start_new_session=True)
os.close(_s7)
_sess7 = _tsmod.Session("unit-sid-2", "unit2", _slow_out6, lambda sid, r: None)
_sess7._fd = _m7
_sess7._proc = _proc7
_sess7._pump = _th6.Thread(target=_tsmod._pump_fd, args=(_sess7,), daemon=True, name="unit-pump2")
_sess7._pump.start()
check("terminal: the busy pump really is stuck in _emit (the next check is not vacuous)",
      _in_emit6.wait(timeout=10), "the pump never reached the output callback")

_closed_by7 = []
_real_close7 = os.close


def _spy_close7(fd):
    if fd == _m7:
        _closed_by7.append(_th6.current_thread().name)
    return _real_close7(fd)


# Released while the teardown is waiting on the pump: with the join this lets the pump retire and
# close its own descriptor, without it the caller has already closed it.
_th6.Timer(0.2, _gate6.set).start()
os.close = _spy_close7
try:
    _sess7.close("unit test")
finally:
    os.close = _real_close7
check("terminal: a BUSY pump still closes its own descriptor, not the caller",
      _closed_by7[:1] == ["unit-pump2"],
      "the pty master was closed by %r while the pump was still inside the output callback and "
      "would go on to read that descriptor number again" % (_closed_by7,))
_gate6.set()
if _proc7.poll() is None:
    _proc7.kill()

# ── the opt-in host-terminal sudo grant, RUN rather than read ─────────────────────────────────
# The operator asked for sudo in the terminal that PROMPTS for a password, which is a different
# thing from the NOPASSWD grants everywhere else in this file: a compromised panel holds no secret
# that a password-required rule turns into root. That distinction is one word (`NOPASSWD:`) in one
# line, so it is checked by running the writer and reading what it actually produced, not by
# grepping the script for the word.
#
# The function is extracted from install.sh and executed with the sudoers directory pointed at a
# temp dir — the same shape as the snapshot/rollback checks above, which exist because a
# reimplementation would pass whatever install.sh happens to say.
_inst6 = open(os.path.join(_root, "install.sh"), encoding="utf-8").read()
_fn_i6 = _inst6.find("write_terminal_sudo_grant() {")
_fn_j6 = _inst6.find("\n}\n", _fn_i6)
check("install.sh: write_terminal_sudo_grant is where this gate expects it",
      _fn_i6 != -1 and _fn_j6 > _fn_i6, "start=%d end=%d" % (_fn_i6, _fn_j6))
check("install.sh: ...and it writes its OWN sudoers file, not the narrow grant's",
      "/etc/sudoers.d/00-linuxgsm-panel-terminal" in _inst6[_fn_i6:_fn_j6 + 3],
      "the terminal grant does not name a separate file — writing into "
      "/etc/sudoers.d/linuxgsm-panel would be erased by the next self-update, and would put a "
      "general rule in the file the narrow-grant gates guard")

# ...and it must sort BEFORE the narrow grant. sudo reads /etc/sudoers.d in lexical order and the
# LAST matching rule wins, so a general `ALL=(ALL) ALL` in a later-sorting file overrides the
# narrow grant's NOPASSWD line for the helper — every privileged panel action then waits for a
# password nothing can type. Confirmed on a real host: the same two rules worked or broke purely
# by which filename sorted last. Renaming either file is enough to reintroduce it, so compare them
# the way sudo does.
_terminal_grant_name6 = "00-linuxgsm-panel-terminal"
_narrow_grant_name6 = "linuxgsm-panel"
check("install.sh: the terminal grant sorts BEFORE the narrow grant in /etc/sudoers.d",
      sorted([_terminal_grant_name6, _narrow_grant_name6])[0] == _terminal_grant_name6,
      "%r sorts after %r, so its general rule becomes the last match for the helper command and "
      "every privileged panel action starts asking for a password"
      % (_terminal_grant_name6, _narrow_grant_name6))
check("install.sh: ...and that is the name it actually writes",
      "/etc/sudoers.d/%s" % _terminal_grant_name6 in _inst6,
      "install.sh does not write /etc/sudoers.d/%s" % _terminal_grant_name6)
check("uninstall.sh: ...and the uninstaller removes that same file",
      "/etc/sudoers.d/%s" % _terminal_grant_name6
      in open(os.path.join(_root, "uninstall.sh"), encoding="utf-8").read(),
      "a general sudo rule would be left naming an account that no longer exists")

_fn_src6 = _inst6[_fn_i6:_fn_j6 + 3] if _fn_j6 > _fn_i6 > -1 else ""
_sud_dir6 = _tempfile.mkdtemp(prefix="panel-tsudo-")
_grant_f6 = os.path.join(_sud_dir6, "00-linuxgsm-panel-terminal")


def _run_tsudo6(setting, pw_state="P"):
    """Run the real function with the sudoers dir redirected. Returns (rc, output)."""
    body = _fn_src6.replace("/etc/sudoers.d", _sud_dir6)
    script = (
        "set -u\n"
        "RUN_AS_ROOT=1\n"
        "PANEL_USER=paneluser\n"
        "ok(){ echo \"OK: $*\"; }\n"
        "warn(){ echo \"WARN: $*\"; }\n"
        "info(){ echo \"INFO: $*\"; }\n"
        "die(){ echo \"DIE: $*\"; exit 9; }\n"
        "visudo(){ return 0; }\n"
        # `passwd -S` prints: <user> <status> <date> ... — status P means a usable password.
        "passwd(){ echo \"paneluser %s 01/01/2020 0 99999 7 -1\"; }\n" % pw_state
        + body + "\n"
        + ("" if setting is None else "PANEL_TERMINAL_SUDO=%s\nexport PANEL_TERMINAL_SUDO\n" % setting)
        + "write_terminal_sudo_grant\n")
    r = _sh_sub.run(["bash", "-c", script], capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr)


_rc6, _out6 = _run_tsudo6(None)
check("install.sh: with PANEL_TERMINAL_SUDO unset, nothing is written",
      _rc6 == 0 and not os.path.exists(_grant_f6),
      "an update granted the panel user general sudo without being asked: rc=%s %r" % (_rc6, _out6))

_rc6, _out6 = _run_tsudo6("1")
_granted6 = open(_grant_f6, encoding="utf-8").read().strip() if os.path.exists(_grant_f6) else ""
check("install.sh: PANEL_TERMINAL_SUDO=1 writes the grant",
      _rc6 == 0 and _granted6 != "", "rc=%s file=%r out=%r" % (_rc6, _granted6, _out6))
check("install.sh: ...and the grant REQUIRES a password (this is the whole point)",
      "NOPASSWD" not in _granted6,
      "the terminal grant is passwordless — that is NOPASSWD:ALL for the panel user, which is "
      "exactly what the narrow grant exists to avoid: %r" % (_granted6,))
check("install.sh: ...and it grants the panel user, not everyone",
      _granted6.startswith("paneluser "), "grant=%r" % (_granted6,))
check("install.sh: ...and the file is not world-readable",
      os.path.exists(_grant_f6) and (os.stat(_grant_f6).st_mode & 0o777) == 0o440,
      "mode=%o" % (os.stat(_grant_f6).st_mode & 0o777 if os.path.exists(_grant_f6) else 0))

# An account with no password can never answer the prompt, so the feature would look broken rather
# than absent. It has to say so.
_rc6, _out6 = _run_tsudo6("1", pw_state="L")
check("install.sh: ...and it warns when the account has no usable password",
      "passwd paneluser" in _out6,
      "nothing told the operator that sudo can never succeed until a password is set: %r" % (_out6,))

_rc6, _out6 = _run_tsudo6("0")
check("install.sh: PANEL_TERMINAL_SUDO=0 removes the grant again",
      _rc6 == 0 and not os.path.exists(_grant_f6),
      "rc=%s still present: %r" % (_rc6, _out6))
_shutil.rmtree(_sud_dir6, ignore_errors=True)

# ── the terminal's ssh argv cannot be turned into ssh OPTIONS ─────────────────────────────────
# ssh has no `--` to end its options, so an argv element that begins with `-` is read as one, and
# `server.host` is stored data an admin types. HOST_RE does NOT stop this on its own — `-o` and
# `--` both match it. What makes it safe is that the destination is always `user@host` and
# LINUX_USER_RE forces the username to start with a letter or underscore, so the element can never
# begin with a dash. That is a property, not a comment, so it is driven here with hostile hosts.
_tsm6 = _il6.import_module("panel.ops.terminal_session")


class _HostileRemote6:
    username = "root"
    port = 22
    auth_method = "tailscale"

    def __init__(self, host):
        self.host = host


# _resolve_ts_host reaches for tailscale's MagicDNS domain for a bare name; stub it so this test
# asks about argv construction and nothing else (and never touches the network).
_core6 = _il6.import_module("panel.ops.ssh_manager._core")
_real_resolve6 = _core6._resolve_ts_host
_core6._resolve_ts_host = lambda srv: srv.host
try:
    _hostile6 = ["-oProxyCommand=id", "--", "-o", "-F/tmp/evil", "-E", "1.2.3.4", "box.ts.net"]
    _bad6 = []
    for _h6 in _hostile6:
        _argv6 = _tsm6._ssh_argv(_HostileRemote6(_h6))
        # Everything after the fixed option block is data. None of it may look like an option.
        _tail6 = _argv6[len(_argv6) - 1:]
        if any(_e.startswith("-") for _e in _tail6):
            _bad6.append((_h6, _argv6))
        if not _argv6[-1].startswith("root@"):
            _bad6.append((_h6, _argv6))
    check("terminal: a hostile remote host cannot become an ssh option", not _bad6,
          "ssh would parse the destination as an option for: %r" % (_bad6,))
    check("terminal: ...and the check above actually built something",
          _tsm6._ssh_argv(_HostileRemote6("box.ts.net"))[0] == "ssh",
          "argv[0] is not ssh — this gate is asking about the wrong thing")
    # The port is stringified through int(), so a non-numeric port cannot add an argument either.
    _p6 = _HostileRemote6("box.ts.net")
    _p6.port = "22; rm -rf /"
    try:
        _tsm6._ssh_argv(_p6)
        _port_safe6 = False
    except (TypeError, ValueError):
        _port_safe6 = True
    check("terminal: ...and a non-numeric port is rejected rather than passed through",
          _port_safe6, "a port that is not a number reached the ssh command line")
finally:
    _core6._resolve_ts_host = _real_resolve6

# ── the local shell comes from the ACCOUNT, not the environment ───────────────────────────────
# It read os.environ["SHELL"], which systemd does not set — so a root install always took the
# /bin/bash fallback whatever shell the account had. And a --system account may legitimately have
# /usr/sbin/nologin, which spawns a terminal that prints one line and exits.
import pwd as _pwd6
_real_getpw6 = _pwd6.getpwuid


class _FakePw6:
    def __init__(self, sh): self.pw_shell = sh


try:
    _pwd6.getpwuid = lambda uid: _FakePw6("/usr/sbin/nologin")
    check("terminal: a nologin account falls back to a real shell",
          _tsm6._login_shell() == "/bin/bash",
          "the terminal would spawn nologin: %r" % (_tsm6._login_shell(),))
    _pwd6.getpwuid = lambda uid: _FakePw6("/bin/zsh")
    check("terminal: ...and an ordinary account gets its own shell",
          _tsm6._login_shell() == "/bin/zsh", "got %r" % (_tsm6._login_shell(),))
    _pwd6.getpwuid = lambda uid: _FakePw6("")
    check("terminal: ...and an empty passwd shell falls back too",
          _tsm6._login_shell() == "/bin/bash", "got %r" % (_tsm6._login_shell(),))
finally:
    _pwd6.getpwuid = _real_getpw6
check("terminal: the shell is not read from the environment",
      "environ.get(\"SHELL\")" not in _modsrc("panel/ops/terminal_session.py"),
      "$SHELL is back — systemd does not set it, so this silently ignores the account's shell")
# ── a firewall the panel could not READ is not a firewall with nothing in it ──────────────────
# ufw_blocked_ips discarded the return code, so an unreadable firewall answered {} — the same
# thing "no IPs are blocked" answers. _autoblock_reconcile reads "not in blocked" as "needs
# blocking", so every offender looked unblocked and it re-issued a delete+add for each of them,
# every cycle, against a host that was not answering. It already guards its OTHER read the same
# way (`if top is None`); this one was simply missed.
_so6 = _il6.import_module("panel.ops.system_ops")
_real_runverb6 = _so6._run_verb
_UFW_SAMPLE6 = ("Status: active\n"
                "To                         Action      From\n"
                "Anywhere                   DENY IN     203.0.113.9                # panel-autoblock\n")
try:
    _so6._run_verb = lambda *a, **k: ("", "ufw: command not found", 127)
    _failed6 = _so6.ufw_blocked_ips()
    check("firewall: an unreadable firewall answers None, not an empty dict",
          _failed6 is None,
          "answered %r — indistinguishable from 'nothing is blocked'" % (_failed6,))
    _so6._run_verb = lambda *a, **k: (_UFW_SAMPLE6, "", 0)
    _read6 = _so6.ufw_blocked_ips()
    check("firewall: ...and a successful read still parses its rules",
          _read6 == {"203.0.113.9": "panel-autoblock"},
          "parsed %r" % (_read6,))
    _so6._run_verb = lambda *a, **k: ("Status: active\n", "", 0)
    _empty6 = _so6.ufw_blocked_ips()
    check("firewall: ...and a firewall with genuinely nothing blocked still answers {}",
          _empty6 == {}, "answered %r — that would skip the reconcile instead" % (_empty6,))
    # A DISABLED firewall reaches here through the SUCCESSFUL path, which the rc guard cannot see:
    # `ufw status` on an installed-but-inactive host exits 0 and prints exactly one line,
    # "Status: inactive", with no rule rows. The parse found no DENY lines and answered {} — "the
    # panel has blocked nobody" — for a firewall whose stored rules it cannot read. _autoblock
    # reads "not in blocked" as "needs blocking" and `ufw deny from <ip>` STORES a rule and exits 0
    # while inactive, so every offender was re-blocked and audited as applied, hourly, forever,
    # with no packet being dropped.
    _so6._run_verb = lambda *a, **k: ("Status: inactive\n", "", 0)
    _inactive6 = _so6.ufw_blocked_ips()
    check("firewall: an INACTIVE firewall is unreadable (None), not a firewall with nothing in it",
          _inactive6 is None,
          "answered %r — autoblock would re-issue every block against a firewall that is off"
          % (_inactive6,))
    # ...in any language. ufw translates the Status line whole (Dutch: `Status: inactief`), so the
    # English substring test missed it and the inactive firewall read as "nothing blocked" again.
    _so6._run_verb = lambda *a, **k: ("Status: inactief\n", "", 0)
    _inactive6 = _so6.ufw_blocked_ips()
    check("firewall: a TRANSLATED inactive firewall is unreadable (None) too",
          _inactive6 is None, "answered %r" % (_inactive6,))
    _so6._run_verb = lambda *a, **k: (_UFW_SAMPLE6.replace("Status: active", "Status: actief")
                                      .replace("From\n", "From\n--                         ------      ----\n"), "", 0)
    _read6 = _so6.ufw_blocked_ips()
    check("firewall: ...while a translated ACTIVE one still parses its rules (positive control)",
          _read6 == {"203.0.113.9": "panel-autoblock"}, "parsed %r" % (_read6,))
finally:
    _so6._run_verb = _real_runverb6

# ...and the caller must act on the difference, not just receive it.
_mon6 = _il6.import_module("panel.services.monitoring")


class _FakeRemote6:
    name = "unit-host"
    is_local = True
    id = 4242


_denied6 = []
_undenied6 = []
_saved6 = (_mon6.so.fail2ban_attempt_counts, _mon6.so.ufw_blocked_ips,
           _mon6.so.ufw_deny_ip, _mon6.so.ufw_undeny_ip)
try:
    _mon6.so.fail2ban_attempt_counts = lambda *a, **k: {"203.0.113.9": 99999}
    _mon6.so.ufw_deny_ip = lambda ip, tag=None: (_denied6.append(ip), (True, "ok"))[1]
    _mon6.so.ufw_undeny_ip = lambda ip: (_undenied6.append(ip), (True, "ok"))[1]
    _mon6.so.ufw_blocked_ips = lambda: None            # the firewall could not be read
    # Caught, not allowed to propagate: part06 is imported for its side effects, so an exception
    # here takes the other 2000 checks down with it and the run reports a crash instead of a
    # failure. Without the guard this raises AttributeError on None.items() — which IS the
    # failure, so record it as one.
    try:
        _res6 = _mon6._autoblock_reconcile(_FakeRemote6())
    except Exception as _e6:
        _res6 = "raised %r" % (_e6,)
    check("firewall: autoblock does nothing at all when the firewall read failed",
          _res6 == (0, 0) and not _denied6 and not _undenied6,
          "returned %r after denying %r / undenying %r" % (_res6, _denied6, _undenied6))
    _mon6.so.ufw_blocked_ips = lambda: {}              # read fine, nothing blocked yet
    _res6 = _mon6._autoblock_reconcile(_FakeRemote6())
    check("firewall: ...and still blocks an offender when the read SUCCEEDED (positive control)",
          _denied6 == ["203.0.113.9"],
          "denied %r — the guard is refusing every cycle, not just the unreadable ones"
          % (_denied6,))
    check("firewall: ...and a block that WORKED is counted",
          _res6 == (1, 0), "returned %r for one successful block" % (_res6,))
    # ...and one that did NOT work is not. The caller turns these two numbers straight into an
    # audit row ("+%d blocked, -%d released"), so counting attempts means the log records rules
    # that never landed — ufw down, or the host stopped answering mid-cycle.
    _denied6.clear()
    _mon6.so.ufw_deny_ip = lambda ip, tag=None: (_denied6.append(ip), (False, "ufw: command not found"))[1]
    _res6 = _mon6._autoblock_reconcile(_FakeRemote6())
    check("firewall: a block the host REFUSED is not counted as applied",
          _res6 == (0, 0) and _denied6 == ["203.0.113.9"],
          "returned %r after a deny that failed — the audit row would claim a rule that never "
          "landed (attempted: %r)" % (_res6, _denied6))
finally:
    (_mon6.so.fail2ban_attempt_counts, _mon6.so.ufw_blocked_ips,
     _mon6.so.ufw_deny_ip, _mon6.so.ufw_undeny_ip) = _saved6

# ── auto-block must never touch a block the panel did not write ───────────────────────────────
# The blocked-IP readers kept only `panel-` tagged DENY rows, so an operator's own
# `ufw deny from <ip>` read as "not blocked". The reconcile then called ufw_deny_ip, which ran
# `ufw delete deny from <ip>` FIRST — ufw removes a matching rule whatever its comment — and
# inserted a panel-autoblock rule in its place, which it RELEASED once the firewalled (so silent)
# address aged below the threshold. Driven through the real readers and writers: only the verb
# runner is stubbed, and it records every privileged command.
# The operator's denies sit ABOVE the allow: ufw stops at the first match, so only there do they
# block anything (the rules below the allow are the shadowed case, further down). The IPv6 deny
# sits below an IPv4 allow, which never sees its packets.
_ab_listing6 = ("Status: active\n\n"
                "To                         Action      From\n"
                "--                         ------      ----\n"
                "Anywhere                   DENY        203.0.113.9                # panel-autoblock\n"
                "Anywhere                   DENY        203.0.113.7\n"
                "Anywhere                   DENY        203.0.113.8                # ssh brute\n"
                "Anywhere                   REJECT      198.51.100.0/24\n"
                "22/tcp                     DENY        198.51.100.3\n"
                "27015                      DENY        Anywhere\n"
                "22/tcp                     ALLOW       Anywhere\n"
                "Anywhere (v6)              DENY        2001:db8::66\n")
check("autoblock: the deny reader sees EVERY all-ports block, tagging the ones the panel did not write",
      SO._ufw_deny_sources(_ab_listing6) == {"203.0.113.9": "panel-autoblock", "203.0.113.7": "",
                                              "203.0.113.8": "", "198.51.100.0/24": "",
                                              "2001:db8::66": ""},
      "read %r" % (SO._ufw_deny_sources(_ab_listing6),))
check("autoblock: ...and an operator's rule for an address outranks the panel's own tag for it",
      SO._ufw_deny_sources(_ab_listing6 + "Anywhere                   DENY        203.0.113.9\n")
      .get("203.0.113.9") == "",
      "the panel's tag won, so the reconcile could 'release' (delete) the operator's rule")
# ...but an operator's deny BELOW an allow blocks nothing: ufw appends a hand-typed
# `ufw deny from <ip>` after `22/tcp LIMIT` and `27015 ALLOW`, and every packet to those ports
# meets the allow first. Read as "blocked", the reconcile skipped the address, the offenders
# table badged it and the Block button left it alone — while it kept reaching SSH.
_sh_listing6 = ("Status: active\n\n"
                "To                         Action      From\n"
                "--                         ------      ----\n"
                "22/tcp                     LIMIT       Anywhere\n"
                "27015                      ALLOW       Anywhere\n"
                "Anywhere                   DENY        203.0.113.20               # ssh brute!\n"
                "Anywhere                   DENY        203.0.113.21\n"
                "Anywhere                   REJECT      203.0.113.22\n"
                "22/tcp (v6)                LIMIT       Anywhere (v6)\n"
                "Anywhere (v6)              DENY        2001:db8::20\n")
_sh_late6 = {}
_sh_read6 = SO._ufw_deny_sources(_sh_listing6, _sh_late6)
check("autoblock: an operator's deny BELOW an allow of its family is not read as a block",
      not {"203.0.113.20", "203.0.113.21", "203.0.113.22", "2001:db8::20"} & set(_sh_read6),
      "read %r" % (_sh_read6,))
check("autoblock: ...it is handed back as shadowed, with its comment and action",
      _sh_late6.get("203.0.113.20") == {"comment": "ssh brute!", "action": "DENY"}
      and _sh_late6.get("203.0.113.22", {}).get("action") == "REJECT"
      and "2001:db8::20" in _sh_late6, "shadowed %r" % (_sh_late6,))
_sh_above6 = ("Anywhere                   DENY        203.0.113.20\n"
              "22/tcp                     ALLOW       10.0.0.0/8\n"
              "Anywhere                   DENY        203.0.113.21\n"
              "22/tcp                     LIMIT       Anywhere\n")
check("autoblock: ...while one ABOVE the allows, or below an allow for other sources only, still "
      "is (positive control)",
      SO._ufw_deny_sources(_sh_above6) == {"203.0.113.20": "", "203.0.113.21": ""},
      "read %r" % (SO._ufw_deny_sources(_sh_above6),))
# `ufw allow in on tailscale0` — the panel adds it itself, usually before any deny — only ever
# sees tailnet sources. Read as an allow from Anywhere, every operator deny below it looked
# shadowed: badged unblocked while it blocked, and moved on the next Block.
_sh_ts6 = ("Anywhere on tailscale0     ALLOW IN    Anywhere\n"
           "Anywhere                   DENY        203.0.113.30\n"
           "Anywhere                   DENY        100.101.2.3\n"
           "Anywhere (v6) on tailscale0 ALLOW IN   Anywhere (v6)\n"
           "Anywhere (v6)              DENY        2001:db8::30\n")
_sh_ts_late6 = {}
_sh_ts_read6 = SO._ufw_deny_sources(_sh_ts6, _sh_ts_late6)
check("autoblock: an operator's deny below the tailscale0 allow still blocks a public address",
      _sh_ts_read6 == {"203.0.113.30": "", "2001:db8::30": ""},
      "read %r, shadowed %r" % (_sh_ts_read6, _sh_ts_late6))
check("autoblock: ...while a tailnet address below it is shadowed (positive control)",
      set(_sh_ts_late6) == {"100.101.2.3"}, "shadowed %r" % (_sh_ts_late6,))
_ab_verbs6 = []
_ab_saved6 = (SO._run_verb, _mon6.so.fail2ban_attempt_counts, _mon6.tailnet_exempt_ips,
              _mon6._autoblock_threshold, _mon6._whitelist_networks)


def _ab_run6(verb, args=(), **k):
    if verb == "ufw-status":
        return (_ab_listing6, "", 0)
    _ab_verbs6.append((verb, list(args)))
    return ("", "", 0)


try:
    SO._run_verb = _ab_run6
    _mon6.tailnet_exempt_ips = lambda remote, ips: set()
    _mon6._autoblock_threshold = lambda: 20
    _mon6._whitelist_networks = lambda: []
    # .7 and .8 are the operator's, over threshold; .10 has no rule, over threshold; .9 is ours and
    # has aged to nothing; 2001:db8::66 is the operator's and has too.
    _mon6.so.fail2ban_attempt_counts = lambda *a, **k: {"203.0.113.7": 50, "203.0.113.8": 40,
                                                        "203.0.113.10": 30}
    # ...and .11 carries BOTH a panel auto-block and the operator's own rule, and has aged out.
    _ab_listing6 += ("Anywhere                   DENY        203.0.113.11               # panel-autoblock\n"
                     "Anywhere                   DENY        203.0.113.11\n")
    _res6 = _mon6._autoblock_reconcile(_FakeRemote6())
    check("autoblock: an operator's own block is neither deleted nor replaced",
          not any(a[0] in ("203.0.113.7", "203.0.113.8") for v, a in _ab_verbs6),
          "commands run for the operator's addresses: %r" % (_ab_verbs6,))
    check("autoblock: ...nor 'released' when its address falls below the threshold",
          ("ufw-delete-deny-ip", ["2001:db8::66"]) not in _ab_verbs6, repr(_ab_verbs6))
    check("autoblock: ...even when a panel auto-block sits beside it for the same address "
          "(a release deletes both)",
          ("ufw-delete-deny-ip", ["203.0.113.11"]) not in _ab_verbs6, repr(_ab_verbs6))
    check("autoblock: ...while an unblocked offender is blocked with an INSERT alone (positive control)",
          ("ufw-deny-ip", ["203.0.113.10", "panel-autoblock"]) in _ab_verbs6
          and ("ufw-delete-deny-ip", ["203.0.113.10"]) not in _ab_verbs6, repr(_ab_verbs6))
    check("autoblock: ...and the panel's own stale auto-block is still released (positive control)",
          ("ufw-delete-deny-ip", ["203.0.113.9"]) in _ab_verbs6 and _res6 == (1, 1),
          "returned %r, ran %r" % (_res6, _ab_verbs6))
    # The Block button runs the same writer. On an operator's rule it must leave it alone; on the
    # panel's own auto-block it re-tags it as manual (which the reconcile then never releases).
    _ab_verbs6.clear()
    _okb6, _msgb6 = SO.ufw_deny_ip("203.0.113.7")
    check("block: an address the operator already blocked is left as it is",
          _okb6 is True and not _ab_verbs6, "ran %r (%r)" % (_ab_verbs6, _msgb6))
    _ab_verbs6.clear()
    SO.ufw_deny_ip("203.0.113.9", tag="panel-block")
    check("block: ...and an auto-block is re-tagged as manual (positive control)",
          _ab_verbs6 == [("ufw-delete-deny-ip", ["203.0.113.9"]),
                         ("ufw-deny-ip", ["203.0.113.9", "panel-block"])], repr(_ab_verbs6))
    # The remote twin shares the decision; its reader must hand it the same answer.
    _ab_rp6 = _sm_core.run_privileged
    try:
        _ab_rverbs6 = []
        _sm_core.run_privileged = lambda s, v, a=(), **k: (
            (_ab_listing6, "", 0) if v == "ufw-status" else (_ab_rverbs6.append((v, list(a))), ("", "", 0))[1])
        _okr6, _ = _sm_hosts.remote_ufw_deny_ip(NS(name="h"), "203.0.113.8", tag="panel-autoblock")
        check("block (remote): an operator's commented block is left as it is",
              _okr6 is True and not _ab_rverbs6, "ran %r" % (_ab_rverbs6,))
        _sm_core.run_privileged = lambda s, v, a=(), **k: ("Status: inactive\n", "", 0)
        check("block (remote): an INACTIVE remote firewall is unreadable (None), as on the panel host",
              _sm_hosts.remote_ufw_blocked_ips(NS(name="h")) is None,
              "answered %r" % (_sm_hosts.remote_ufw_blocked_ips(NS(name="h")),))
    finally:
        _sm_core.run_privileged = _ab_rp6

    # ── a shadowed operator deny is MOVED to the top, still theirs ──
    # A plain insert does nothing here: ufw keeps one rule per match and answers a second
    # `deny from <ip>` with "Skipping inserting existing rule", exit 0 — a "Blocked" that changed
    # nothing. So the move is a delete and an insert carrying the operator's comment, never a
    # panel- tag (which the reconcile would one day release).
    _sh_verbs6, _sh_fail6 = [], set()

    def _sh_run6(verb, args=(), **k):
        if verb == "ufw-status":
            return (_sh_listing6, "", 0)
        _sh_verbs6.append((verb, list(args)))
        return ("", "ERROR: boom", 1) if verb in _sh_fail6 else ("", "", 0)
    SO._run_verb = _sh_run6
    _okm6, _msgm6 = SO.ufw_deny_ip("203.0.113.20")
    check("block: an operator's deny below the allows is moved to the top under THEIR comment",
          _okm6 is True and _sh_verbs6 == [("ufw-delete-deny-ip", ["203.0.113.20"]),
                                          ("ufw-deny-ip", ["203.0.113.20", "ssh brute"])],
          "ran %r (%r)" % (_sh_verbs6, _msgm6))
    check("block: ...and the blocked-IP read the offenders table uses no longer badges it",
          "203.0.113.20" not in (SO.ufw_blocked_ips() or {}), repr(SO.ufw_blocked_ips()))
    _sh_verbs6.clear()
    _mon6.so.fail2ban_attempt_counts = lambda *a, **k: {"203.0.113.21": 50}
    _resm6 = _mon6._autoblock_reconcile(_FakeRemote6())
    check("autoblock: an offender whose own deny is shadowed is moved, not skipped or re-tagged",
          _resm6 == (1, 0) and _sh_verbs6 == [("ufw-delete-deny-ip", ["203.0.113.21"]),
                                             ("ufw-deny-ip", ["203.0.113.21", ""])],
          "returned %r, ran %r" % (_resm6, _sh_verbs6))
    _sh_verbs6.clear()
    _okv6, _ = SO.ufw_deny_ip("2001:db8::20")
    _okj6, _ = SO.ufw_deny_ip("203.0.113.22")
    check("block: ...but an IPv6 or REJECT one, which could not be put back, is refused untouched",
          _okv6 is False and _okj6 is False and not _sh_verbs6, "ran %r" % (_sh_verbs6,))
    _sh_fail6.add("ufw-deny-ip")
    _okf6, _msgf6 = SO.ufw_deny_ip("203.0.113.20")
    check("block: ...and a move whose insert fails tries to put the rule back, and says it failed",
          _okf6 is False and [v for v, a in _sh_verbs6].count("ufw-deny-ip") == 2
          and "could not be put back" in _msgf6, "ran %r (%r)" % (_sh_verbs6, _msgf6))
    _sh_fail6.clear()
    _ab_rp6 = _sm_core.run_privileged
    try:
        _sh_verbs6.clear()
        _sm_core.run_privileged = lambda s, v, a=(), **k: _sh_run6(v, a)
        _okrm6, _ = _sm_hosts.remote_ufw_deny_ip(NS(name="h"), "203.0.113.20", tag="panel-autoblock")
        check("block (remote): the remote twin moves a shadowed operator deny the same way",
              _okrm6 is True and _sh_verbs6 == [("ufw-delete-deny-ip", ["203.0.113.20"]),
                                                ("ufw-deny-ip", ["203.0.113.20", "ssh brute"])],
              "ran %r" % (_sh_verbs6,))
    finally:
        _sm_core.run_privileged = _ab_rp6
    SO._run_verb = _ab_run6

    # ── ...and it sees every offender, not the display's top 100 ──
    # The reconcile read fail2ban_top_ips(100): over-threshold addresses ranked below 100 were never
    # blocked, and a blocked one — which logs nothing more — was released while still over the
    # threshold once 100 newer ones out-counted it. Driven through the real count reader.
    _mon6.so.fail2ban_attempt_counts = _ab_saved6[1]
    _wave6 = ["198.18.%d.%d" % (i // 250, i % 250 + 1) for i in range(150)]
    _loglines6 = "".join("2026-09-20 10:00:00,000 fail2ban.filter [1]: INFO [sshd] Found %s\n" % ip
                         for i, ip in enumerate(_wave6) for _ in range(25 + i))
    _loglines6 += "".join("2026-09-20 10:00:00,000 fail2ban.filter [1]: INFO [sshd] Found 203.0.113.9\n"
                          for _ in range(21))     # ours: still over threshold, ranked 151st
    _ab_verbs6.clear()

    def _ab_run6b(verb, args=(), **k):
        if verb == "f2b-log-lines":
            return (_loglines6, "", 0)
        return _ab_run6(verb, args, **k)
    SO._run_verb = _ab_run6b
    _res6 = _mon6._autoblock_reconcile(_FakeRemote6())
    _blocked6 = {a[0] for v, a in _ab_verbs6 if v == "ufw-deny-ip"}
    check("autoblock: every address over the threshold is blocked, not just the top 100",
          _blocked6 == set(_wave6), "blocked %d of %d" % (len(_blocked6 & set(_wave6)), len(_wave6)))
    check("autoblock: ...and an auto-block still over the threshold is not released for ranking low",
          ("ufw-delete-deny-ip", ["203.0.113.9"]) not in _ab_verbs6, "released while at 21 >= 20")
finally:
    (SO._run_verb, _mon6.so.fail2ban_attempt_counts, _mon6.tailnet_exempt_ips,
     _mon6._autoblock_threshold, _mon6._whitelist_networks) = _ab_saved6

# ── "could not check" must not render as "all files match" ────────────────────────────────────
# _compute_panel_integrity fails SAFE: when git cannot be run it answers clean:true WITH
# verified:false, and its comment says "never claim the files are verified-clean when we couldn't
# actually run the check". loadIntegrity() then read `clean` alone and showed the green tick, so
# the front end undid the back end's refusal. Driven in a rendered panel before this was fixed:
# the tick appeared and the server's own message was shown nowhere.
_integ_js6 = open(os.path.join(_root, "static", "js", "remote_manage_host.js"),
                  encoding="utf-8").read()
_fn6 = _integ_js6.split("function loadIntegrity()", 1)[-1].split("\nfunction ", 1)[0]
check("integrity: the pane reads `verified`, not just `clean`",
      "d.verified" in _fn6,
      "loadIntegrity ignores the flag the server sets when it could not run the check")
check("integrity: ...and it tests it BEFORE deciding the files are clean",
      "d.verified" in _fn6 and "d.clean" in _fn6
      and _fn6.index("d.verified") < _fn6.index("d.clean"),
      "the clean branch runs first, so an unverified answer still renders the green tick")
_rm_html6 = open(os.path.join(_root, "templates", "remote_manage.html"), encoding="utf-8").read()
check("integrity: ...and there is somewhere to SAY so",
      'id="diag-integrity-unknown"' in _rm_html6 and "diag-integrity-unknown" in _fn6,
      "nothing renders the reason, so an unverifiable host shows an empty panel instead")

# ── the terminal must not say "Connected" before anything has connected ───────────────────────
# term_ready means the session was OPENED. For a pty and for a paramiko channel that is the same
# thing as connected, but the tailscale transport is a plain `ssh -tt` and Popen returns the
# moment the PROCESS starts — so an unreachable host read "Connected to <host>." for the whole
# seventeen seconds ssh spent dialling, and only then admitted the session had closed. Measured
# against a host that does not answer: status at t+3s was "Connected", the real answer
# ("connect to host ... Connection timed out") arrived at t+16.9s.
#
# The first byte back is the honest signal whatever the transport, so the claim moved to the
# output handler. A reachable host's prompt lands in milliseconds and it reads the same as before
# — verified at 150ms for both a local pty and a real remote.
_ht_src6 = open(os.path.join(_root, "static", "js", "host_terminal.js"), encoding="utf-8").read()


def _handler_body6(event):
    """The body of one sock.on('<event>', ...) handler, up to the next handler."""
    marker = "sock.on('%s'" % event
    if marker not in _ht_src6:
        return None
    rest = _ht_src6.split(marker, 1)[1]
    nxt = rest.find("sock.on('")
    return rest[:nxt] if nxt != -1 else rest


_ready6 = _handler_body6("term_ready")
_outh6 = _handler_body6("term_output")
check("terminal: the term_ready and term_output handlers are both there to check",
      _ready6 is not None and _outh6 is not None,
      "a handler was renamed — re-point this gate (ready=%r output=%r)"
      % (_ready6 is not None, _outh6 is not None))
check("terminal: term_ready does not claim a connection",
      _ready6 is not None and "Connected to" not in _ready6,
      "the session being OPENED is not the host being reachable — the tailscale transport's "
      "Popen returns before ssh has dialled, so this reads 'Connected' at a host that is down")
check("terminal: ...and the first byte back is what claims it",
      _outh6 is not None and "Connected to" in _outh6,
      "nothing ever upgrades the status, so a working terminal never says it connected")
check("terminal: ...claimed once, not on every chunk",
      _outh6 is not None and "sawOutput" in _outh6,
      "without a latch this re-sets the status on every chunk of output, overwriting anything "
      "the exit handler has since put there")

# ── ...and the socket it all arrives on has to carry the mount ────────────────────────────────
# `io()` with no options uses socket.io-client's built-in default path, "/socket.io" at the SITE
# ROOT (confirmed in the vendored client, v4.7.5: (n=n||{}).path||"/socket.io"). Under a mount —
# Tailscale Serve with tailscale_mount "/lgsm" — that handshake is outside the mount and 404s, so
# `connect` never fires, term_open is never emitted, and the page sits on "Connecting…" over a
# blank black box for ever: term_error and disconnect BOTH need a connection that was never made,
# so nothing was ever shown. The console on the same panel keeps working, because panel.js and
# server_detail.js prefix their path — this was the one socket in the panel that did not.
_ht_io6 = re.search(r"sock\s*=\s*io\(([^;]*)\)", _ht_src6)
check("terminal: the socket handshake path carries the mount prefix",
      _ht_io6 is not None and "MOUNT" in _ht_io6.group(1) and "/socket.io" in _ht_io6.group(1),
      "io(%s) — on a sub-path panel that asks the site root, and the page never connects"
      % (_ht_io6.group(1) if _ht_io6 else "<no `sock = io(...)` call found>"))
_pjs6 = open(os.path.join(_root, "static", "js", "panel.js"), encoding="utf-8").read()
check("terminal: ...the same way its sibling client does (positive control)",
      "MOUNT + '/socket.io'" in _pjs6,
      "panel.js does not prefix it either, so the gate above is asserting a shape nothing has — "
      "re-point it at whatever the siblings do now")
_cerr6 = _handler_body6("connect_error")
check("terminal: a handshake that never completes says so, instead of 'Connecting…' for ever",
      _cerr6 is not None and "_status(" in _cerr6,
      "nothing writes to #term-status when the socket never connects, so the only symptom of a "
      "wrong path is a page that claims it is connecting and never stops")

# ── a message must not send the reader to a file that is not there ────────────────────────────
# PERMISSION_DESCRIPTIONS[USE_TERMINAL] read "powerful — see SECURITY.md", and SECURITY.md does
# not exist in this repo — so the one permission whose consequences most need explaining pointed
# an admin at nothing. Written by me, in the commit that added the permission.
#
# Scanned across the strings the panel SHOWS, not just that table: a docs pointer is only worth
# printing if it resolves.
_doc_refs6 = []
for _pyf6 in sorted(glob.glob(os.path.join(_root, "panel", "**", "*.py"), recursive=True)):
    _rel6 = os.path.relpath(_pyf6, _root)
    for _lineno6, _line6 in enumerate(open(_pyf6, encoding="utf-8"), 1):
        if _line6.lstrip().startswith("#"):
            continue                      # a comment is for a reader of the source, not a user
        for _m6 in re.finditer(r"""["']([^"']*?\b([A-Z][A-Za-z0-9_-]*\.md)\b[^"']*)["']""", _line6):
            _fname6 = _m6.group(2)
            if not os.path.exists(os.path.join(_root, _fname6)):
                _doc_refs6.append("%s:%d -> %s" % (_rel6, _lineno6, _fname6))
check("docs: no user-facing string points at a file that does not exist",
      not _doc_refs6,
      "dangling: %s — the reader is told to go and read something that is not in the repo"
      % ("; ".join(_doc_refs6),))
# ...and the check is not vacuous: it must be able to SEE a .md reference at all.
check("docs: ...and the scan can actually find a .md reference (not a dead regex)",
      len(re.findall(r"""["']([^"']*?\b([A-Z][A-Za-z0-9_-]*\.md)\b[^"']*)["']""",
                     'x = "see README.md for more"')) == 1,
      "the pattern matches nothing, so the gate above would pass against any dangling pointer")

# ── the route-coverage tool must not flatter its own answer ───────────────────────────────────
# tools/route_coverage.py reports which route bodies no suite enters. Its first version shared one
# work tree across all nine suites, and three of them refuse to run when data/panel.db exists —
# they print SKIP and **exit 0**. So the first suite's database silently disabled four of the
# others and the tool reported a SMALLER untested set than the truth: a measurement wrong in the
# direction that looks like progress.
#
# Two properties make the answer honest, and both are one line each to delete by accident.
_rc_src6 = open(os.path.join(_root, "tools", "route_coverage.py"), encoding="utf-8").read()
_rc_code6 = "\n".join(_ln for _ln in _rc_src6.splitlines()
                      if not _ln.lstrip().startswith("#"))          # not its own explanation
# Scoped to the LOOP, not to the file: _report() clears data/ too, so searching the whole source
# matched that copy and the gate passed with the clearing deleted from the loop — which is the
# only place it prevents anything. Caught by mutation, which is the entire point of doing it.
_rc_loop6 = _rc_code6.split("def _run_suites", 1)[-1].split("\ndef ", 1)[0]
check("route_coverage: data/ is cleared before each suite runs",
      "rmtree" in _rc_loop6 and '"data"' in _rc_loop6,
      "nothing removes data/ inside the suite loop, so the suites that refuse to run against an "
      "existing database will SKIP and the tool will report fewer untested routes than there are")
check("route_coverage: ...and a SKIPped suite stops it reporting at all",
      'startswith("SKIP:")' in _rc_code6 and "refusing to report" in _rc_code6,
      "a suite that printed SKIP and exited 0 would be counted as having covered everything")
_rc_suites6 = sorted(re.findall(r'"([a-z_]+)"',
                                _rc_src6.split("SUITES = (", 1)[1].split(")", 1)[0]))
_repo_suites6 = sorted(os.path.basename(_p)[:-len("_test.py")]
                       for _p in glob.glob(os.path.join(_root, "tests", "*_test.py")))
check("route_coverage: ...and it runs every suite the repo has",
      _rc_suites6 == _repo_suites6,
      "SUITES=%r but tests/ has %r — a suite missing from it makes every route only that suite "
      "covers look untested" % (_rc_suites6, _repo_suites6))

# ── the sudo hint has to know WHICH install it is talking about ───────────────────────────────
# It only knew about the root install: "if sudo refuses rather than asking for a password, that
# account has no general sudo entry ... re-run the installer with PANEL_TERMINAL_SUDO=1". On a
# PER-USER install the panel runs as the operator's own account, which on a cloud image usually
# has NOPASSWD:ALL — so sudo neither refuses nor prompts. Reported from a live panel: a full
# `sudo apt full-upgrade` ran to completion underneath that banner.
import pwd as _pwd7
_ts7 = _il6.import_module("panel.ops.terminal_session")
_so7 = _il6.import_module("panel.ops.system_ops")
_saved7 = (_pwd7.getpwuid, _so7._is_system_service)


class _Pw7:
    pw_name = "ubuntu"
    pw_shell = "/bin/bash"


try:
    _pwd7.getpwuid = lambda uid: _Pw7()
    _so7._is_system_service = lambda: False           # per-user install
    _peruser7 = _ts7.sudo_hint(None, True)
    _so7._is_system_service = lambda: True            # root/system install
    _system7 = _ts7.sudo_hint(None, True)
finally:
    (_pwd7.getpwuid, _so7._is_system_service) = _saved7

check("sudo hint: a per-user install is not told sudo will refuse",
      "refuses rather than asking" not in _peruser7,
      "the per-user hint still explains how to enable a sudo that already works: %r" % (_peruser7,))
check("sudo hint: ...it says the shell has whatever sudo that account has",
      "full root" in _peruser7 and "ubuntu" in _peruser7,
      "the per-user hint does not say the terminal may already be root: %r" % (_peruser7,))
check("sudo hint: a SYSTEM install still gets the narrow-grant explanation",
      "PANEL_TERMINAL_SUDO=1" in _system7 and "privileged helper" in _system7,
      "the root-install hint lost the advice that is correct for it: %r" % (_system7,))
check("sudo hint: ...and the two installs are not told the same thing",
      _peruser7 != _system7,
      "both install types render identical text, so one of them is wrong")

# ── a paste the program is not reading must not stop the panel ────────────────────────────────
# os.write on a BLOCKING pty master waits for the foreground program to read it. eventlet greens
# os.write but a blocking descriptor gives it nothing to poll, so the wait is the whole hub, not
# one greenlet — the entire panel stops serving. Measured on this machine: writing 20 KB of
# line-terminated text to a pty whose child was not reading never returned and no other greenlet
# ran at all; 8160 bytes went straight through and 12288 did not.
#
# Fixed by not writing from here AT ALL: write() queues and the pump — the one greenlet that owns
# the descriptor — drains it. The first attempt waited for writability from this side and raised
# "Second simultaneous write on fileno N", which write() caught and turned into a closed session,
# so every keystroke killed the terminal. eventlet allows one greenlet per descriptor per event.
#
# Driven through a thread with a join deadline ON PURPOSE: if this regresses the call never
# returns, and a test that hangs the suite reports "crashed" instead of naming the broken check.
_wt_master, _wt_slave = _pty6.openpty()
_wt_proc = _sp6.Popen([sys.executable, "-c", "import time; time.sleep(30)"],
                      stdin=_wt_slave, stdout=_sp6.DEVNULL, stderr=_sp6.DEVNULL,
                      start_new_session=True)
os.close(_wt_slave)
os.set_blocking(_wt_master, False)
_wt_told = []
_wt_sess = _tsmod.Session("wt", "wt", lambda sid, d: _wt_told.append(d), lambda sid, r: None)
_wt_sess._fd = _wt_master
_wt_done = []


def _wt_run():
    _t0 = _time.time()
    _wt_sess.write(("x" * 79 + "\n") * 250)          # 20 KB: measured above as the blocking size
    _wt_done.append(_time.time() - _t0)


_wt_thread = _th6.Thread(target=_wt_run, daemon=True)
_wt_thread.start()
try:
    _wt_thread.join(timeout=10)
except BaseException:
    # BaseException, not Exception: eventlet's green join RAISES eventlet.timeout.Timeout rather
    # than returning quietly, and that class derives from BaseException BY DESIGN so it cannot be
    # swallowed by a generic handler. An exception at module level takes the whole suite down —
    # which is what happened the first two times this guard ran against the regression it exists
    # to catch. _wt_done staying empty is what the check below reports.
    pass
check("terminal: a paste the program is not reading RETURNS instead of hanging",
      bool(_wt_done),
      "Session.write did not come back within 10s — writing to the descriptor from here waits on "
      "the whole event loop, not just this session")
check("terminal: ...immediately, because it only queues",
      bool(_wt_done) and _wt_done[0] < 1.0,
      "took %r seconds; the pump owns the descriptor and should be doing the writing" % (_wt_done,))
check("terminal: ...and the session survives it",
      not _wt_sess.closed,
      "writing closed the session — 'Second simultaneous write on fileno N' caught by write() "
      "turns every keystroke into a dead terminal")
# ...and input beyond the bound is refused out loud rather than buffered without limit.
_wt_told[:] = []
_wt_sess.write("y" * (_tsmod._MAX_PENDING_INPUT + 1))
check("terminal: input past the queue bound is dropped WITH a message",
      any("dropped" in _d for _d in _wt_told),
      "input vanished with nothing on screen to say so: %r" % (_wt_told[:2],))
try:
    os.close(_wt_master)
except OSError:
    pass                      # the pump owns it in a real session; here there is no pump
_wt_proc.kill()

# ── seven defects an adversarial review of this session's own terminal turned up ──────────────
_ht_js7 = open(os.path.join(_root, "static", "js", "host_terminal.js"), encoding="utf-8").read()
_ts_src7 = _modsrc("panel/ops/terminal_session.py")
_htr_src7 = _modsrc("panel/routes/host_terminal.py")

# (a) The pump must close the pty master ONLY if it still owned it. os.close sat outside the
# `if sess._fd == fd` claim, so when _close_fd's join timed out and took the fd, the kernel handed
# that NUMBER to the next open() and the pump closed a descriptor belonging to something else. The
# `except OSError` cannot catch it: closing a recycled number succeeds.
# Parsed, not indented: the mutated shape put os.close inside a `try:` at the same indentation as
# the claim's body, so an indentation comparison could not tell the two apart.
_pf_tree7 = _ast6.parse(_ts_src7)
_pf_fn7 = next((n for n in _ast6.walk(_pf_tree7)
                if isinstance(n, _ast6.FunctionDef) and n.name == "_pump_fd"), None)


def _closes_outside_if7(fn):
    """os.close(...) calls in fn that are NOT inside any If."""
    guarded = set()
    for node in _ast6.walk(fn):
        if isinstance(node, _ast6.If):
            for inner in _ast6.walk(node):
                if isinstance(inner, _ast6.Call):
                    guarded.add(id(inner))
    loose = []
    for node in _ast6.walk(fn):
        if isinstance(node, _ast6.Call) and id(node) not in guarded \
           and getattr(node.func, "attr", None) == "close" \
           and getattr(getattr(node.func, "value", None), "id", None) == "os":
            loose.append(node.lineno)
    return loose


_loose7 = _closes_outside_if7(_pf_fn7) if _pf_fn7 else ["_pump_fd not found"]
check("terminal: the pump closes the pty master only inside its ownership claim",
      _pf_fn7 is not None and not _loose7,
      "os.close sits outside `if sess._fd == fd` at %r — there it closes whatever process-wide "
      "descriptor has since been given that number, and `except OSError` cannot see it because "
      "closing a recycled number succeeds" % (_loose7,))

# (b) A failed Popen must not leak the pty pair. open_session's handler calls sess.close(), but
# nothing is attached to the session yet, so every teardown step is a no-op.
_tsmod7 = _il6.import_module("panel.ops.terminal_session")


class _FailRemote7:
    name = "fail"; host = "127.0.0.1"; port = 22; username = "root"
    auth_method = "local"; is_local = True; display_name = "fail"; id = 99


def _open_fds7():
    try:
        return len(os.listdir("/proc/self/fd"))
    except OSError:
        return None


_saved_popen7 = _tsmod7.subprocess.Popen
_tsmod7.subprocess.Popen = lambda *a, **k: (_ for _ in ()).throw(BlockingIOError(11, "EAGAIN"))
try:
    _before7 = _open_fds7()
    for _i7 in range(5):
        try:
            _tsmod7.open_session("leak-%d" % _i7, _FailRemote7(), True, user_key=1,
                                 on_output=lambda s, d: None, on_exit=lambda s, r: None)
        except Exception:
            pass
    _after7 = _open_fds7()
finally:
    _tsmod7.subprocess.Popen = _saved_popen7
check("terminal: a shell that fails to start leaks no descriptors",
      _before7 is None or _after7 is None or _after7 <= _before7 + 1,
      "five failed opens took the process from %s to %s open descriptors — two per attempt is a "
      "pty pair and a /dev/pts device each time, and the operator's answer to 'could not start a "
      "shell' is to click again" % (_before7, _after7))
check("terminal: ...and leaves no session registered either",
      _tsmod7.count() == 0, "sessions left behind: %d" % _tsmod7.count())

# (b2) A close that lands while the transport is still CONNECTING. The session is registered
# before the opener runs and a paramiko connect can take the whole ssh_timeout; a close in that
# window found nothing attached, and the opener then hung a client and a login shell on a session
# already marked closed. close() is idempotent, so nothing ever released them. Driven through the
# real open_session with the connect stubbed on _core, closing the socket's session mid-connect.
_core_ts7 = _il6.import_module("panel.ops.ssh_manager._core")


class _RaceChan7:
    def __init__(self):
        self.closed = False

    def settimeout(self, _t):
        pass

    def recv_ready(self):
        return False

    def exit_status_ready(self):
        return self.closed

    def resize_pty(self, **_k):
        pass

    def close(self):
        self.closed = True


class _RaceClient7:
    def __init__(self):
        self.closed, self.chan = False, None

    def invoke_shell(self, **_k):
        self.chan = _RaceChan7()
        return self.chan

    def close(self):
        self.closed = True


class _RaceRemote7:
    name = "race"; host = "192.0.2.9"; port = 22; username = "root"
    auth_method = "key"; is_local = False; display_name = "race"; id = 98


def _open_racing7(close_mid_connect):
    made = []

    def _conn(server, force_new=False, pooled=True):
        if close_mid_connect:
            _tsmod7.close_for_sid("race-sid", "the connection closed")
        made.append(_RaceClient7())
        return made[-1]

    saved = _core_ts7.get_connection
    _core_ts7.get_connection = _conn
    raised = sess = None
    try:
        try:
            sess = _tsmod7.open_session("race-sid", _RaceRemote7(), False, user_key=7,
                                        on_output=lambda s, d: None, on_exit=lambda s, r: None)
        except _tsmod7.TerminalError as e:
            raised = e
    finally:
        _core_ts7.get_connection = saved
    return made, raised, sess


_rc_made7, _rc_err7, _rc_sess7 = _open_racing7(True)
_rc_client7 = _rc_made7[0] if _rc_made7 else None
check("terminal: a session closed while connecting releases the client it then got",
      _rc_client7 is not None and _rc_client7.closed
      and _rc_client7.chan is not None and _rc_client7.chan.closed,
      "client closed=%s, shell channel closed=%s — an authenticated SSH connection with a live "
      "login shell stays open to that host until the panel restarts, outside the idle sweeper and "
      "the session caps" % (getattr(_rc_client7, "closed", None),
                            getattr(getattr(_rc_client7, "chan", None), "closed", None)))
check("terminal: ...and open_session reports it rather than handing back a dead session",
      _rc_err7 is not None and _rc_sess7 is None and _tsmod7.count() == 0,
      "raised=%r returned=%r registered=%d — on_term_open then records the host and emits "
      "term_ready for a socket that is gone" % (_rc_err7, _rc_sess7, _tsmod7.count()))
_ok_made7, _ok_err7, _ok_sess7 = _open_racing7(False)
check("terminal: ...while an uninterrupted open keeps its client (positive control)",
      _ok_err7 is None and _ok_sess7 is not None and _ok_made7 and not _ok_made7[0].closed,
      "raised=%r client closed=%s" % (_ok_err7, _ok_made7 and _ok_made7[0].closed))
if _ok_sess7 is not None:
    _ok_sess7.close("done")

# (b3) One socket's map entry must name the session that is actually live on it. close() popped
# by sid, and teardown yields (kill grace, pump join) — so a term_open after the idle sweeper had
# started closing the old shell registered a new one that the old close() then deleted from the
# map. That shell ran on, unreachable by input, the disconnect hook, the sweeper and the caps.
# The yield is stood in for by registering from inside the first teardown step.
_own_a7 = _tsmod7.Session("own-sid", "own-a", lambda s, d: None, lambda s, r: None)
_own_b7 = _tsmod7.Session("own-sid", "own-b", lambda s, d: None, lambda s, r: None)
_own_a7.user_key = _own_b7.user_key = 5
_tsmod7._register(_own_a7, 5)
_own_mid7 = []


def _own_mid_close7():
    try:
        _tsmod7._register(_own_b7, 5)
        _own_mid7.append("registered")
    except _tsmod7.TerminalError as e:
        _own_mid7.append("refused: %s" % e)


_own_a7._close_chan = _own_mid_close7
_own_a7.close("closed after 15 minutes with no input")
check("terminal: a session that finishes closing leaves a newer one on its socket registered",
      _own_mid7 == ["registered"] and _tsmod7.get("own-sid") is _own_b7,
      "during teardown: %r; registered now: %r — the new shell keeps running with nothing "
      "able to reach or close it" % (_own_mid7, getattr(_tsmod7.get("own-sid"), "label", None)))
_own_b7.close("done")
check("terminal: ...while a session's own close still removes it (positive control)",
      _tsmod7.get("own-sid") is None and _tsmod7.count() == 0,
      "left registered: %d" % _tsmod7.count())

_live_a7 = _tsmod7.Session("live-sid", "live-a", lambda s, d: None, lambda s, r: None)
_live_b7 = _tsmod7.Session("live-sid", "live-b", lambda s, d: None, lambda s, r: None)
_live_a7.user_key = _live_b7.user_key = 5
_tsmod7._register(_live_a7, 5)
try:
    _tsmod7._register(_live_b7, 5)
    _live_refused7 = False
except _tsmod7.TerminalError:
    _live_refused7 = True
check("terminal: a second session is refused, not written over a LIVE one on the same socket",
      _live_refused7 and _tsmod7.get("live-sid") is _live_a7,
      "refused=%s, registered=%r — the overwritten shell keeps its pump running and can no "
      "longer be closed" % (_live_refused7, getattr(_tsmod7.get("live-sid"), "label", None)))
_live_a7.close("done")

# (c) One decoder per SESSION, not per chunk: a read boundary lands wherever the kernel puts it,
# so a multi-byte character split across two reads became two replacement characters forever.
# Driven through the REAL pump over a real pty, in two writes with a pause between them so the
# reads genuinely split the character. Calling _decoder.decode() directly tested the decoder and
# passed happily with the pump still decoding each chunk on its own.
_got7 = []
_dm7, _ds7 = _pty6.openpty()
_sess7 = _tsmod7.Session("dec", "dec", lambda sid, d: _got7.append(d), lambda sid, r: None)
_sess7._fd = _dm7
_sess7._pump = _th6.Thread(target=_tsmod7._pump_fd, args=(_sess7,), daemon=True)
_sess7._pump.start()
_raw7 = ("─" * 3).encode("utf-8")           # U+2500, three bytes each
os.write(_ds7, _raw7[:4])                   # boundary falls mid-character
_time.sleep(0.4)
os.write(_ds7, _raw7[4:])
_time.sleep(0.4)
_seen7 = "".join(_got7)
_sess7.close("done")
try:
    os.close(_ds7)
except OSError:
    pass
check("terminal: a character split across two reads survives intact",
      "\ufffd" not in _seen7 and _seen7.count("─") == 3,
      "the pump emitted %r — a box-drawing run, an accented name or an emoji in a MOTD arrives "
      "corrupted when each read is decoded on its own" % (_seen7,))

# (d) Teardown must not depend on the audit bookkeeping: _sid_host[sid] is written AFTER
# open_session returns, and the session is registered BEFORE the transport opens.
_cna7 = _htr_src7.split("def _close_and_audit", 1)[-1].split("\n    @", 1)[0]
_cna_code7 = "\n".join(_l for _l in _cna7.splitlines() if not _l.lstrip().startswith("#"))
check("terminal: a disconnect tears the session down before consulting the audit map",
      "close_for_sid" in _cna_code7 and "_sid_host.pop" in _cna_code7
      and _cna_code7.index("close_for_sid") < _cna_code7.index("_sid_host.pop"),
      "_close_and_audit returns early when there is no _sid_host entry, which is exactly the "
      "state a socket is in while term_open is still connecting — the shell stays up and the "
      "per-user slot stays held")

# (e) The reconnect guard has to actually hold: socket.io reconnects by itself.
# Counted, not searched: `var ... opened = false` is the declaration and must stay, so a bare
# `"opened = false" not in src` matched it and failed against correct code.
_reset7 = [_ln.strip() for _ln in _ht_js7.splitlines()
           if "opened" in _ln and "= false" in _ln.replace("=false", "= false")
           and not _ln.lstrip().startswith(("//", "*"))
           and not _ln.lstrip().startswith("var ")]
check("terminal: the reconnect guard is never cleared",
      not _reset7,
      "`opened` is reset at %r, so socket.io's own reconnect re-fires the connect handler and "
      "silently opens a SECOND shell while the status line says to reload" % (_reset7,))

# (f) Socket events are not HTTP requests, so before_request never runs for them.
# Comments and docstrings stripped: the explanation beside each guard names the very identifier
# the check looks for, so searching the raw source passed with the guard deleted.
_htr_code7 = re.sub(r'"""(?:.|\n)*?"""', "", _htr_src7)
_htr_code7 = "\n".join(_l for _l in _htr_code7.splitlines() if not _l.lstrip().startswith("#"))
check("terminal: the socket events enforce the forced password change themselves",
      re.search(r"\bmust_change_password\b", _htr_code7) is not None,
      "must_change_password is enforced by an @app.before_request, which a Socket.IO event never "
      "enters — a handed-over temporary password could open a shell")

# (g) ...and per-host access is re-checked while the shell is live, not only when it opened.
_input_body7 = _htr_code7.split("def on_term_input", 1)[-1].split("\n    @", 1)[0]
check("terminal: host access is re-validated during a live session",
      "_still_allowed" in _input_body7
      and re.search(r"\bcan_access_remote\b", _htr_code7) is not None,
      "access is checked only at open, so revoking it leaves the live shell typing into the host")

# (h) ...and on a TIMER, because a shell following a log sends no events at all. smoke_test drives
# sweep_revoked_terminals itself; this pins that register() actually runs it: supervise() is
# handed a function that calls it. From the AST — both names appear in comments and docstrings.
_htr_tree7 = _ast.parse(_htr_src7)
_htr_reg7 = next((n for n in _ast.walk(_htr_tree7)
                  if isinstance(n, _ast.FunctionDef) and n.name == "register"), None)
_htr_inner7 = {n.name: n for n in _ast.walk(_htr_reg7)
               if isinstance(n, _ast.FunctionDef)} if _htr_reg7 else {}


def _calls_name7(node, name):
    return any(isinstance(c, _ast.Call) and isinstance(c.func, _ast.Name) and c.func.id == name
               for c in _ast.walk(node))


_htr_supervised7 = [c.args[1].id for c in _ast.walk(_htr_reg7 or _ast.Module(body=[]))
                    if isinstance(c, _ast.Call) and isinstance(c.func, _ast.Name)
                    and c.func.id == "supervise" and len(c.args) >= 2
                    and isinstance(c.args[1], _ast.Name)]
_htr_sweeps7 = [n for n in _htr_supervised7
                if n in _htr_inner7 and _calls_name7(_htr_inner7[n], "sweep_revoked_terminals")]
check("terminal: register() runs the revocation sweep on a timer",
      bool(_htr_sweeps7),
      "supervised: %r — none calls sweep_revoked_terminals, so a revoked login's shell that is "
      "sent no input streams its output until the 15-minute idle sweep" % (_htr_supervised7,))

# ── the local shell needs a CONTROLLING terminal, not just its own session ────────────────────
# start_new_session=True calls setsid, which is necessary and not sufficient: the child inherits
# the pty slave as a descriptor rather than opening it, so it ends up with no controlling terminal
# at all. No controlling terminal means no foreground process group, which means the line
# discipline has nobody to deliver SIGINT to — Ctrl-C does nothing.
#
# It read as working because bash only warns ("cannot set terminal process group", "no job control
# in this shell") and carries on. fish refuses and exits, which is how it was finally noticed. The
# child now issues TIOCSCTTY in preexec_fn, after setsid.
#
# Driven with bash for predictable job control, and every wait is bounded so a regression fails
# instead of hanging the suite.
_ctty_saved7 = _tsmod7._login_shell
_tsmod7._login_shell = lambda: "/bin/bash"
_ctty_out7 = []
# ...and with SIGINT IGNORED in this process, on purpose. An ignored disposition survives fork and
# exec and bash hands it to every job, so a panel started with it ignored (from a script, with `&`)
# gave the local terminal jobs that ^C could not stop. This check failed exactly that way whenever
# the suite itself was launched in the background, and passed in the foreground. The child now
# resets it; ignoring it here makes the check cover that reset on every run instead of by launch.
import signal as _ctty_sig7
_ctty_sigint7 = _ctty_sig7.signal(_ctty_sig7.SIGINT, _ctty_sig7.SIG_IGN)


class _CttyRemote7:
    name = "ctty"; is_local = True; display_name = "ctty"; id = 1


try:
    _ctty_sess7 = _tsmod7.open_session("ctty-sid", _CttyRemote7(), True, user_key=1,
                                       on_output=lambda s, d: _ctty_out7.append(d),
                                       on_exit=lambda s, r: None)

    def _ctty_children7():
        _r = _sh_sub.run(["pgrep", "-P", str(_ctty_sess7._proc.pid)],
                         capture_output=True, text=True)
        return [_x for _x in _r.stdout.split() if _x]

    _t0_7 = _time.time()
    while _time.time() - _t0_7 < 5 and not "".join(_ctty_out7):
        _time.sleep(0.2)
    # A SOURCE gate, deliberately, and the reason is worth stating: no behavioural probe on this
    # machine can tell the fix from its absence. setsid detaches the child from any controlling
    # terminal, but a session leader that then OPENS a tty acquires it — so bash and dash both end
    # up with one either way, and /proc/<pid>/stat's tty_nr reads non-zero in both cases
    # (measured: 34823 with the preexec_fn and 34823 without). fish is the one that notices,
    # because it calls tcgetpgrp before that acquisition happens, and it exits: "No TTY for
    # interactive shell". Testing that would mean requiring fish on every runner.
    #
    # So this pins the mechanism rather than pretending to observe its effect, and the checks
    # below stay as an end-to-end "the terminal works and job control functions" pass — they are
    # not a guard for THIS fix and are not labelled as one.
    _open_local_src7 = _ts_src7.split("def _open_local", 1)[-1].split("\ndef ", 1)[0]
    check("terminal: the local shell is given a controlling terminal before exec",
          "TIOCSCTTY" in _open_local_src7 and "preexec_fn=" in _open_local_src7,
          "setsid alone leaves the child with no controlling terminal, so there is no foreground "
          "process group for the line discipline to send SIGINT to — bash carries on with a "
          "warning, fish exits outright")

    _ctty_sess7.write("sleep 120\n")
    _t0_7 = _time.time()
    while _time.time() - _t0_7 < 6 and not _ctty_children7():
        _time.sleep(0.2)
    _ctty_started7 = _ctty_children7()
    check("terminal: ...a foreground job really starts (the next check needs one)",
          bool(_ctty_started7),
          "nothing was running, so the Ctrl-C check below would pass against a dead shell")

    def _ctty_is_fg7(pids):
        """Is one of `pids` the job itself yet, holding the terminal's foreground? bash forks the
        job, hands it the terminal (tcsetpgrp), and only then does the child reset its signal
        handlers and exec `sleep`. A ^C before the exec lands on bash's own handler in the forked
        child (or on bash's group, before the tcsetpgrp) and the job never sees it: the check
        below failed on a loaded machine with nothing wrong in the code."""
        for _p in pids:
            try:
                with open("/proc/%s/stat" % _p) as _fh:
                    _raw = _fh.read()
                _comm = _raw[_raw.index("(") + 1:_raw.rindex(")")]
                _st = _raw[_raw.rindex(")") + 1:].split()
            except (OSError, ValueError):
                continue
            # After the comm: state ppid pgrp session tty_nr tpgid.
            if _comm == "sleep" and len(_st) > 5 and _st[2] == _st[5]:
                return True
        return False

    _t0_7 = _time.time()
    while _time.time() - _t0_7 < 6 and not _ctty_is_fg7(_ctty_children7()):
        _time.sleep(0.1)
    _ctty_sess7.write("\x03")
    _t0_7 = _time.time()
    while _time.time() - _t0_7 < 6 and _ctty_children7():
        _time.sleep(0.2)
    check("terminal: ...and Ctrl-C interrupts it",
          bool(_ctty_started7) and not _ctty_children7(),
          "the job %r survived Ctrl-C — without a controlling terminal the line discipline has no "
          "foreground process group to signal, and with SIGINT left ignored from the panel's own "
          "launch the job ignores it" % (_ctty_started7,))
finally:
    _tsmod7._login_shell = _ctty_saved7
    _ctty_sig7.signal(_ctty_sig7.SIGINT, _ctty_sigint7)
    try:
        _tsmod7.close_for_sid("ctty-sid", "test over")
    except Exception:
        pass

# ── the update card's count and its list must be the same set ─────────────────────────────────
# Reported from a live panel: "Update available: v0.10.0-alpha (1 commit behind)" with no commits
# listed underneath. The count came from the RAW log and the list from the runtime-filtered one —
# `len(rc_log) or behind_target` used the filtered number when it had one and the unfiltered
# number when it did not — so an update made only of test or tooling commits announced itself and
# then had nothing to show.
#
# `git` is STUBBED. The suites run in a throwaway tree built from `git ls-files`, which carries no
# .git at all, so every git call there fails and returns nothing — the first version of this asked
# the real repo for a real range and "no runtime commits" passed because the answer was empty for
# the wrong reason.
_uc_saved7 = _so6._git
_UC_LOG7 = ("bf64153\tMeasure the routes nothing enters (#327)\n"
            "tests/smoke_test.py\n"
            "tools/route_coverage.py\n")
try:
    _so6._git = lambda *a, **k: (_UC_LOG7, "", 0)
    _uc_filtered7 = _so6._runtime_changelog("HEAD..origin/main")
    _uc_all7 = _so6._runtime_changelog("HEAD..origin/main", runtime_only=False)
finally:
    _so6._git = _uc_saved7
check("update card: a commit touching only tests and tooling is dropped by the runtime filter",
      _uc_filtered7 == [],
      "expected no runtime commits, got %r" % (_uc_filtered7,))
check("update card: ...but it can still be listed when that is all there is",
      len(_uc_all7) == 1 and _uc_all7[0].startswith("bf64153"),
      "the unfiltered changelog is %r — with nothing to list, the card shows a count it cannot "
      "explain" % (_uc_all7,))
# ...and the two fields are built from ONE name, so they cannot drift apart again.
_ucs7 = _modsrc("panel/ops/system_ops.py")
_uc_body7 = _ucs7.split("def _compute_update_status", 1)[-1]
_uc_code7 = "\n".join(_l for _l in _uc_body7.splitlines() if not _l.lstrip().startswith("#"))
_uc_behind7 = re.search(r'"behind":\s*len\((\w+)\)', _uc_code7)
_uc_changes7 = re.search(r'"changes":\s*(\w+)\[', _uc_code7)
# The name check alone does NOT catch this — reverting the fix leaves both fields reading the same
# variable and only removes the fallback, so it passed against the bug. What has to be pinned is
# that the list the card shows falls back to the unfiltered log when the filtered one is empty.
check("update card: an update with no runtime commits still has something to show",
      "runtime_only=False" in _uc_code7,
      "_compute_update_status never asks for the unfiltered changelog, so an update made only of "
      "docs, tests or tooling reports a count with an empty list underneath it")
check("update card: the count and the changelog are built from the same list",
      _uc_behind7 is not None and _uc_changes7 is not None
      and _uc_behind7.group(1) == _uc_changes7.group(1),
      "behind counts %r while changes lists %r — whichever is filtered differently is the one the "
      "operator cannot reconcile"
      % (_uc_behind7 and _uc_behind7.group(1), _uc_changes7 and _uc_changes7.group(1)))
