"""Part 44 of the unit suite: review 1008's system_ops and debug-report findings.

* A timed-out subprocess raises eventlet's ORIGINAL TimeoutExpired in this (monkey-patched)
  process: every runner that promises a "timed out" answer must catch both classes.
* configure_panel_fail2ban judges a refused jail/filter write by its rc, not by the old jail.
* The debug report: an unread systemd state is never "no unit file"; configured secrets are mapped
  in their plaintext; the report's own vocabulary is never a pseudonymised name; the unprivileged
  plain journal read is a forward window; auth.log is compared only when it covers the 24 h.

HOW IT RUNS. Each runner is handed the exception class the green subprocess really raises (a
stand-in `run`), so no process sleeps. Nothing touches the network, sudo or the checkout's data/.
"""
import os
import subprocess as _sp44  # nosec B404 - only its run attribute is stood in for, never called
import tempfile as _tf44
import time as _time44

from unit.part01 import SO, check, config
from unit.part02 import _orig_so_run as _so_run_before_leaks44
from unit.part10 import _p7_defined
from unit.part20 import _patch, _patched
from panel.ops import tailscale_integration as _ts44
from panel.ops.debug_report import _src_journal as _sj44
from panel.ops.debug_report import _src_systemd as _sd44
from panel.ops.debug_report import install as _inst44
from panel.ops.debug_report import network as _nw44
from panel.ops.debug_report import privacy as _pv44
from panel.ops.debug_report import process as _proc44
from panel.ops.debug_report._base import Ctx as _Ctx44

_TMP44 = _tf44.mkdtemp(prefix="lgsm-p44-")

# ── timeouts: both TimeoutExpired classes ───────────────────────────────────────────────────────
try:
    from eventlet.patcher import original as _orig44
    _ORIG_TE44 = _orig44("subprocess").TimeoutExpired
except Exception:  # noqa: BLE001 - recorded by the precondition check below
    _ORIG_TE44 = _sp44.TimeoutExpired

check("timeouts (precondition): this suite runs monkey-patched, so the ORIGINAL TimeoutExpired is "
      "not the green one -- without that the checks below would pass on the old code",
      not issubclass(_ORIG_TE44, _sp44.TimeoutExpired), repr(_ORIG_TE44))


def _raise_te44(*a, **_k):
    raise _ORIG_TE44(a[0] if a else "cmd", 1)


def _so_defined44(name, *roots):
    """system_ops.<name> as the module defines it: by this part, _run is an earlier part's stub
    (part03 assigns one and never puts it back; see part10's _p7_defined)."""
    fn = _p7_defined(SO, name, *(roots or (getattr(SO, name),)))
    return fn if fn is not None else (lambda *a, **k: "definition not found")


def _timeout_answers44():
    run_def = _so_defined44("_run", _so_run_before_leaks44, SO._run)
    git_def, probe_def = _so_defined44("_git"), _so_defined44("_helper_probe_run")
    with _patched():
        _patch(_sp44, "run", _raise_te44)
        # Not a sudo argv: the suite's sudo shim (tools/nosudo_runner.py) answers one itself.
        _patch(SO, "_helper_probe_argv", lambda: ["true"])
        _patch(_sd44, "scope", lambda: "user")
        _patch(_sd44, "run", _raise_te44)
        _patch(_inst44, "run_version", _raise_te44)
        out = {}
        for name, fn in (("_git", lambda: git_def(["status"], timeout=1)),
                         ("_run", lambda: run_def("true", timeout=1)),
                         ("_helper_probe_run", lambda: probe_def().get("outcome")),
                         ("_run_ts", lambda: _ts44._run_ts(["status"])),
                         ("unit_show", lambda: _sd44.unit_show().get("why")),
                         ("_sudo_version", lambda: _inst44._sudo_version("/usr/bin/sudo"))):
            try:
                out[name] = fn()
            except Exception as exc:  # noqa: BLE001 - the defect: it escaped
                out[name] = "raised %s" % type(exc).__name__
    return out


_te44 = _timeout_answers44()
check("timeouts: _git, _run, the helper probe, tailscale's runner, unit_show and the sudo version "
      "read each answer their own 'timed out' when eventlet's run() raises the ORIGINAL "
      "TimeoutExpired (a 500 from switch-branch; a whole Diagnostics section errored)",
      _te44 == {"_git": ("", "git timed out", -1), "_run": ("", "Command timed out", -1),
                "_helper_probe_run": "timeout", "_run_ts": ("", "tailscale command timed out", -1),
                "unit_show": "timeout", "_sudo_version": "version unreadable (TimeoutExpired)"},
      repr(_te44))


# ── configure_panel_fail2ban: a refused write is a failure ──────────────────────────────────────
def _f2b_write_refused44(which):
    verbs = []

    def _write(path, content):
        return ("", "refused", 1) if path == which else ("", "", 0)
    with _patched():
        _patch(SO, "_run", lambda cmd, *a, **k: ("yes", "", 0))
        _patch(SO, "_run_verb", lambda verb, args=(), timeout=30, merge_stderr=True:
               (verbs.append(verb), ("", "", 0))[1])
        _patch(SO, "_write_root_file", _write)
        # The OLD jail is up: the status poll alone said "now protecting".
        _patch(SO, "panel_fail2ban_status", lambda: {"installed": True, "enabled": True})
        _patch(SO, "panel_jail_health", lambda a, p, i=None: dict.fromkeys(SO._PANEL_JAIL_CHECKS, False))
        auth = os.path.join(_TMP44, "logs", "auth.log")
        got = SO.configure_panel_fail2ban(auth, 8443, ["203.0.113.9"])
        via = SO.ensure_panel_fail2ban(auth, 8443, ["203.0.113.9"])
    return got, via, verbs


_f2b_jail44 = _f2b_write_refused44(SO._F2B_PANEL_JAIL)
_f2b_filter44 = _f2b_write_refused44(SO._F2B_PANEL_FILTER)
check("fail2ban: a jail or filter write that is refused is a failure (through ensure_panel_fail2ban "
      "too), nothing is reloaded -- the old jail being up is not 'now protecting'",
      _f2b_jail44[0][0] is False and "jail file" in _f2b_jail44[0][1] and _f2b_jail44[1][0] is False
      and _f2b_filter44[0][0] is False and "filter file" in _f2b_filter44[0][1]
      and not any(v in ("f2b-reload", "service-restart", "service-enable-now")
                  for v in _f2b_jail44[2] + _f2b_filter44[2]),
      repr((_f2b_jail44, _f2b_filter44)))


# ── process: an unread systemd state is not "no unit file" ──────────────────────────────────────
def _process_with44(shared):
    with _patched():
        _patch(_proc44._src_systemd, "shared", shared)
        _patch(_proc44, "_PARTS", (("Service", _proc44._service_lines),
                                   ("Unit file", _proc44._drift_lines)))
        res = _proc44.section_process(_Ctx44())
    return "\n".join(res.lines), str(res.verdict)


def _unit_timeout44(ctx):
    raise TimeoutError("memo deadline")


_pu44 = _process_with44(_unit_timeout44)
_pn44 = _process_with44(lambda ctx: {"scope": None, "props": {}, "error": "unreadable",
                                     "why": "no-unit-file", "rc": None})
check("process: when the systemd read itself raised, Unit file says it is unknown (not 'none at "
      "either path') and the verdict says 'systemd state unread' (not 'NOT the unit's MainPID')",
      "**Unit file**: unknown (systemd state could not be read)" in _pu44[0]
      and "none at either path" not in _pu44[0] and "systemd state unread" in _pu44[1]
      and "MainPID" not in _pu44[1], repr(_pu44))
check("process: ...while a measured 'no unit file' still prints 'none at either path'",
      "**Unit file**: none at either path" in _pn44[0] and "started by hand" in _pn44[1], repr(_pn44))


# ── privacy: the configured secrets, as plaintext ───────────────────────────────────────────────
def _scrubbed44(st, text):
    ctx = _Ctx44()
    ctx._memo["privacy"] = (True, st)
    return _pv44.scrub(ctx, text)


def _secret_map44():
    tg, nt = "9f3a7c1e5b2d8a6f4c0e", "tkshort7731"
    hook = "https://discord.com/api/webhooks/1234567890/HookTok7731abc"
    st = _pv44._State()
    _pv44._names_bot(st, {"chat_id": "42", "token": config.encrypt_secret(tg),
                          "webhook": config.encrypt_secret(hook)}, "chat_id")
    _pv44._names_ntfy(st, {"topic": "", "token": config.encrypt_secret(nt)})
    out = _scrubbed44(st, "tg %s here; ntfy %s here; hook token HookTok7731abc alone" % (tg, nt))
    leaked = [s for s in (tg, nt, "HookTok7731abc") if s in out]
    # No cred_key: the stored form only, and no key is created to read it.
    absent = config.CRED_KEY_FILE.with_name("cred_key.absent44")
    with _patched():
        _patch(config, "CRED_KEY_FILE", absent)
        forms = _pv44._dbr_secret_forms("enc:v1:" + "A" * 100)
    return leaked, out, forms, absent.exists()


_sm44 = _secret_map44()
check("privacy: a configured bot token, ntfy token and webhook (stored encrypted) are mapped by "
      "their PLAINTEXT, the webhook's token segment too -- the stored ciphertext never matched a "
      "log line", _sm44[0] == [] and "[secret]" in _sm44[1], repr(_sm44[:2]))
check("privacy: ...and with no cred_key the stored form alone is used and no key is created",
      _sm44[2] == ["enc:v1:" + "A" * 100] and _sm44[3] is False, repr(_sm44[2:]))


# ── privacy: the report's own words are never a name ────────────────────────────────────────────
def _own_words44():
    st = _pv44._State()
    for i, (name, kind) in enumerate((("Public", "tag"), ("Private", "group"), ("tailnet", "tag"),
                                      ("redacted", "user"), ("failed", "tag"), ("email", "group"),
                                      ("Quokka7731", "tag")), 1):
        st.add(name, kind, i)
    return _scrubbed44(st, "public 2 · tailnet 1 · private 0; address public IPv4; seen from "
                           "[ip:public]; [redacted]; 1 failed; [email]; tag Quokka7731")


_ow44 = _own_words44()
check("privacy: a tag or group named after a word of the report's own (public, private, tailnet, "
      "redacted, failed, email) leaves the report's text and markers whole; a real name is still "
      "pseudonymised",
      all(s in _ow44 for s in ("public 2 · tailnet 1 · private 0", "address public IPv4",
                               "[ip:public]", "[redacted]", "1 failed", "[email]"))
      and "Quokka7731" not in _ow44 and "[tag-7]" in _ow44, _ow44)


# ── journal: the unprivileged plain read is a forward window ────────────────────────────────────
def _journal_plain44(n_lines):
    calls = []

    def _run(argv, timeout=5, cap=None):
        calls.append(list(argv))
        if len(argv) > 1 and argv[1].startswith("_SYSTEMD_USER_UNIT="):
            return "".join("Oct 08 10:00:0%d h p[1]: line %d\n" % (i, i) for i in range(n_lines)), "", 0
        return "", "", 0
    with _patched():
        _patch(SO, "_debug_run", _run)
        _patch(_sj44, "_privileged_allowed", lambda so: False)
        got = _sj44.read(3, timeout=5)
    plain = [a for a in calls if len(a) > 1 and a[1].startswith("_SYSTEMD_USER_UNIT=")]
    return got, plain


_jp44, _jpa44 = _journal_plain44(2)
_jf44, _jfa44 = _journal_plain44(3)
check("journal: without sudo, the plain read of this account's unit on the SYSTEM journal is a "
      "forward window (--since --lines=+N), never -n N (which walks the whole journal)",
      len(_jpa44) == 1 and "--since=" + _sj44._PLAIN_FIELD_SINCE in _jpa44[0]
      and "--lines=+3" in _jpa44[0] and "-n" not in _jpa44[0]
      and _jp44.get("source") == "user-unit" and len(_jp44.get("lines") or []) == 2
      and _jp44.get("cut") is False, repr((_jp44, _jpa44)))
check("journal: ...and a window that comes back full is said to be cut (its oldest N), as a "
      "filtered read's is", _jf44.get("cut") is True and len(_jf44.get("lines") or []) == 3
      and _jf44.get("filtered") is False, repr(_jf44))


# ── auth.log: compared only when it covers the 24 h ─────────────────────────────────────────────
def _authlog44(rotated):
    d = _tf44.mkdtemp(dir=_TMP44)
    path = os.path.join(d, "auth.log")
    now = _time44.time()
    with open(path, "w", encoding="utf-8") as fh:
        for age in (3600, 1800, 600):
            fh.write("%s panel login failed from 203.0.113.%d\n"
                     % (_time44.strftime("%Y-%m-%d %H:%M:%S", _time44.localtime(now - age)), age % 250))
    if rotated:
        open(path + ".1", "w").close()
    return _nw44._authlog_text(_nw44.authlog_scan(path), True, 6000)


_ar44, _af44 = _authlog44(True), _authlog44(False)
check("auth.log: rotated within the 24 h, its count is not held against the audit log's (no ✗ that "
      "says the fail2ban feed is broken); a file that is its whole history still is",
      "3 failed-login lines in 24 h (audit log says 6000; not compared" in _ar44 and "✗" not in
      _ar44.split("·")[1] and "(audit log says 6000 ✗)" in _af44, repr((_ar44, _af44)))
