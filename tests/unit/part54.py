"""Part 54 of the unit suite: review 1011b's core, system_ops, ssh-core and Tailscale findings.

* Tailscale Funnel is per LISTENER, so a Serve write for the panel never changes it for another app.
* (further sections are added below, one per finding)

HOW IT RUNS. Every outside call is a stand-in (patched with part20's _patch / _patched, undone at
the end of each block); nothing touches the network, sudo, a real host or the checkout's data/.
The Tailscale section puts tests/unit/fake_tailscale.py (part32's stateful fake, whose Funnel is
per listener as the real CLI's is) first on PATH for its own block and takes it away after.
"""
import json
import os
import shutil
import sys
import tempfile as _tf54
import types as _types54

from unit.part01 import check
from unit.part20 import _patch, _patched

import app as _app54  # noqa: E402
from panel.ops import tailscale_integration as _ts54  # noqa: E402

NS = _types54.SimpleNamespace
_ROOT54 = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── A02: Funnel is per listener; the panel's Serve write never changes another app's ───────────
_TMP54 = _tf54.mkdtemp(prefix="lgsm-unit-p54-")
_STATE54 = os.path.join(_TMP54, "ts-state.json")
_P54 = "http://127.0.0.1:5000"
_PS54 = "https+insecure://127.0.0.1:5000"
_OTHER54 = "http://127.0.0.1:9180"
_ENV54 = {k: os.environ.get(k) for k in ("PATH", "FAKE_TS_STATE", "FAKE_TS_LOG")}


def _seed54(web, funnel=()):
    with open(_STATE54, "w", encoding="utf-8") as fh:
        json.dump({"web": web, "funnel": list(funnel), "http": []}, fh)
    _ts54._cache["info"] = None


def _state54():
    """({listener: {mount: backend}}, [funnelled listeners]) as the fake now holds them."""
    with open(_STATE54, encoding="utf-8") as fh:
        st = json.load(fh)
    return {p: h for p, h in st.get("web", {}).items() if h}, sorted(st.get("funnel", []))


def _boot54(web, funnel, use_funnel=False):
    _seed54(web, funnel)
    app = NS(config={"BOOT_TLS": True})
    cfg = {"tailscale_setup_done": True, "tailscale_mount": "/lgsm",
           "tailscale_use_funnel": use_funnel, "use_https": True}
    _app54._boot_serve(app, cfg, 5000)
    return app.config.get("BOOT_SERVE")


try:
    os.makedirs(os.path.join(_TMP54, "bin"))
    _wrap54 = os.path.join(_TMP54, "bin", "tailscale")
    with open(_wrap54, "w", encoding="utf-8") as _fh54:
        _fh54.write('#!/bin/sh\nexec "%s" "%s" "$@"\n'
                    % (sys.executable, os.path.join(_ROOT54, "tests", "unit", "fake_tailscale.py")))
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stand-in program this part runs
    os.chmod(_wrap54, 0o700)
    os.environ["PATH"] = os.path.join(_TMP54, "bin") + os.pathsep + os.environ.get("PATH", "")
    os.environ["FAKE_TS_STATE"] = _STATE54
    os.environ["FAKE_TS_LOG"] = os.path.join(_TMP54, "ts-calls.jsonl")
    _verbs54 = []
    with _patched():
        _patch(_ts54, "ensure_operator", lambda: (True, "p54"))
        _patch(_ts54, "allow_tailscale_ufw", lambda: (True, ""))
        _patch(_ts54._so, "_run_verb",
               lambda verb, args, **kw: (_verbs54.append(verb), ("", "refused by part54", 1))[1])
        _patch(_app54, "_remove_serve_leftovers", lambda *a, **k: "none")

        _seed54({"443": {"/": _OTHER54}}, funnel=["443"])
        _r54 = _ts54.setup_tailscale_serve(5000, mount="/lgsm", funnel=False)
        check("tailscale funnel: publishing the panel without Funnel beside another app that IS "
              "funnelled on :443 is refused, and that app stays on the internet",
              (_r54[0], _state54()) == (False, ({"443": {"/": _OTHER54}}, ["443"]))
              and "Funnel is set per listener" in _r54[1] and "/" in _r54[1], repr((_r54, _state54())))

        _seed54({"443": {"/": _OTHER54}})
        _r54 = _ts54.setup_tailscale_serve(5000, mount="/lgsm", funnel=True)
        check("tailscale funnel: ...and publishing the panel WITH Funnel beside a tailnet-only app "
              "on :443 is refused, so that app is not put on the public internet",
              (_r54[0], _state54()) == (False, ({"443": {"/": _OTHER54}}, [])), repr((_r54, _state54())))

        _seed54({"443": {"/": _OTHER54}}, funnel=["443"])
        _r54 = _ts54.setup_tailscale_serve(5000, mount="/lgsm", funnel=True)
        _seed54({"443": {"/lgsm": _P54}})
        _r54b = _ts54.setup_tailscale_serve(5000, mount="/lgsm", funnel=True)
        check("tailscale funnel: (control) a write whose Funnel matches the shared listener, or one "
              "on a listener only the panel uses, is made as asked",
              (_r54, _r54b, _state54()) == ((True, "Tailscale Serve enabled (with Funnel)"),
                                            (True, "Tailscale Serve enabled (with Funnel)"),
                                            ({"443": {"/lgsm": _P54}}, ["443"])),
              repr((_r54, _r54b, _state54())))

        _b54 = _boot54({"443": {"/": _OTHER54, "/lgsm": _P54}}, ["443"])
        check("tailscale funnel: the boot re-point (tailscale_use_funnel off) moves the panel's own "
              "route to the scheme it serves and leaves the shared listener's Funnel on for the other "
              "app", (_b54, _state54()) == ("ok", ({"443": {"/": _OTHER54, "/lgsm": _PS54}}, ["443"])),
              repr((_b54, _state54())))
        _b54 = _boot54({"443": {"/": _OTHER54, "/lgsm": _P54}}, [], use_funnel=True)
        check("tailscale funnel: ...and with tailscale_use_funnel on, a tailnet-only app sharing the "
              "listener is not put on the internet by a restart",
              (_b54, _state54()) == ("ok", ({"443": {"/": _OTHER54, "/lgsm": _PS54}}, [])),
              repr((_b54, _state54())))
        _b54 = _boot54({"443": {"/": _OTHER54}}, ["443"])
        check("tailscale funnel: ...while a boot that would ADD the panel to a funnelled listener "
              "it is not on writes nothing, and says why (failed:shared-funnel)",
              (_b54, _state54()) == ("failed:shared-funnel", ({"443": {"/": _OTHER54}}, ["443"])),
              repr((_b54, _state54())))

        _seed54({"443": {"/": _OTHER54, "/lgsm": _P54}}, funnel=["443"])
        _d54 = _ts54.disable_tailscale_serve("/lgsm", 5000)
        check("tailscale funnel: Disable says Funnel stays on for the listener another app still "
              "holds, rather than implying it is off",
              _d54[0] is True and "Funnel stays on" in _d54[1] and _state54()[1] == ["443"],
              repr((_d54, _state54())))
        check("tailscale funnel: nothing reached the root fallback", _verbs54 == [], repr(_verbs54))
finally:
    for _k54, _v54 in _ENV54.items():
        if _v54 is None:
            os.environ.pop(_k54, None)
        else:
            os.environ[_k54] = _v54
    _ts54._cache["info"] = None
    shutil.rmtree(_TMP54, ignore_errors=True)

# ── A03: an SSH rule in a list, a range or after a destination address is an SSH rule ──────────
from unit.part02 import protect as _protect54  # noqa: E402

_DEST54 = ".".join(["203", "0", "113", "54"])    # a documentation address (TEST-NET-3)


def _fw54(rules, tailscale=(False, False)):
    """{To column: group} of `rules` on a remote whose sshd serves 22."""
    return {(x["port_label"], x["direction"], x.get("iface", "")): x
            for x in _protect54(NS(port=22), rules, tailscale=tailscale, sshd_ports=(22,))}


_fw54_shapes = {}
for _to54 in ("22,80,443/tcp", "20:30/tcp", _DEST54 + " 22/tcp"):
    _g54 = _fw54([_to54 + " ALLOW IN Anywhere", "28960 ALLOW IN Anywhere"])
    _fw54_shapes[_to54] = (_g54[(_to54, "IN", "")]["is_ssh"], _g54[(_to54, "IN", "")]["protected"])
check("firewall: the host's only SSH rule written as a port list (22,80,443/tcp), a range "
      "(20:30/tcp) or to one destination address is recognised and protected",
      set(_fw54_shapes.values()) == {(True, True)}, repr(_fw54_shapes))
_g54 = _fw54(["22/tcp ALLOW IN Anywhere", "23:30/tcp ALLOW IN Anywhere", "2222,80/tcp ALLOW IN Anywhere"])
check("firewall: ...while a list or range that does not include sshd's port is not an SSH rule",
      _g54[("22/tcp", "IN", "")]["protected"]
      and not _g54[("23:30/tcp", "IN", "")]["is_ssh"] and not _g54[("2222,80/tcp", "IN", "")]["is_ssh"],
      repr({k: (v["is_ssh"], v["protected"]) for k, v in _g54.items()}))
_g54 = _fw54(["22/tcp ALLOW IN Anywhere", "22,80/tcp on tailscale0 ALLOW IN Anywhere"],
             tailscale=(True, False))
check("firewall: a tailnet rule naming sshd's port in a list (22,80/tcp on tailscale0) is the "
      "second way in, so the public SSH rule only warns",
      _g54[("22,80/tcp", "IN", "tailscale0")]["is_tailscale"]
      and _g54[("22/tcp", "IN", "")]["warn"] and not _g54[("22/tcp", "IN", "")]["protected"],
      repr({k: (v["is_access"], v["protected"], v["warn"]) for k, v in _g54.items()}))

# ── A03: a ufw ROUTE rule (ALLOW FWD) is not a way into the host ────────────────────────────────
_g54 = _fw54(["22/tcp ALLOW IN Anywhere", "22/tcp ALLOW FWD Anywhere"])
check("firewall: a forwarded SSH rule (`ufw route allow 22/tcp`, ALLOW FWD) is not a way in, so the "
      "host's one real SSH rule stays protected",
      not _g54[("22/tcp", "FWD", "")]["is_ssh"] and _g54[("22/tcp", "IN", "")]["protected"],
      repr({k: (v["is_ssh"], v["protected"], v["warn"]) for k, v in _g54.items()}))
_g54 = _protect54(NS(port=22), ["5000/tcp ALLOW FWD Anywhere", "5000/tcp ALLOW IN Anywhere",
                                "22/tcp ALLOW IN Anywhere"],
                  cfg={"port": 5000, "tailscale_setup_done": False}, is_local=True, sshd_ports=(22,))
check("firewall: ...and a forwarded rule for the panel's port is not the panel rule (the IN one is)",
      [(x["direction"], x["is_panel"]) for x in _g54 if x["port_num"] == "5000"]
      == [("FWD", False), ("IN", True)], repr([(x["direction"], x["is_panel"]) for x in _g54]))

# ── A03: a failed `ufw default deny incoming` with `ufw enable` at 0 is not "NOT enabled" ──────
from unit.part51 import _bootstrap51 as _bootstrap54  # noqa: E402

_bs54_dd = _bootstrap54({("ufw-default", ("deny", "incoming"))})
_bs54_en = _bootstrap54({"ufw-enable"})
check("bootstrap: a failed `ufw default deny incoming` beside a `ufw enable` that worked says UFW is "
      "on and the incoming policy is what failed, never 'the firewall was NOT enabled'",
      _bs54_dd[0] is False and "firewall was NOT enabled" not in _bs54_dd[1]
      and "UFW is on, but its default incoming policy could not be set to deny" in _bs54_dd[1]
      and "not protecting this host" not in _bs54_dd[2], repr(_bs54_dd[:2]))
check("bootstrap: ...while a failed `ufw enable` still says the firewall was NOT enabled",
      _bs54_en[0] is False and "the firewall was NOT enabled: `ufw enable` failed" in _bs54_en[1],
      repr(_bs54_en[:2]))

# ── A02: an EMPTY session or credential key is a missing one on the Diagnostics card too ───────
import pathlib as _pl54  # noqa: E402

from panel.core import config as _cfg54  # noqa: E402
from panel.ops import system_ops as _so54  # noqa: E402


def _keys54(secret, cred):
    """_diag_encryption_keys over key files holding `secret` / `cred` (None: no file)."""
    d = _pl54.Path(_tf54.mkdtemp(prefix="lgsm-unit-p54k-"))
    try:
        for name, body in (("secret_key", secret), ("cred_key", cred)):
            if body is not None:
                (d / name).write_text(body, encoding="utf-8")
        with _patched():
            _patch(_cfg54, "SECRET_FILE", d / "secret_key")
            _patch(_cfg54, "CRED_KEY_FILE", d / "cred_key")
            return _so54._diag_encryption_keys()
    finally:
        shutil.rmtree(d, ignore_errors=True)


_k54 = [_keys54("s" * 64, ""), _keys54("", "c" * 44), _keys54("s" * 64, "c" * 44)]
check("diagnostics: an empty cred_key is not 'Session + credential keys present', an empty "
      "secret_key is 'missing' (fail), and two real keys are still present",
      _k54[0][1] != "Session + credential keys present." and _k54[0][0] == "ok"
      and _k54[1] == ("fail", "Session secret key is missing.")
      and _k54[2] == ("ok", "Session + credential keys present."), repr(_k54))

# ── A02: listing branches keeps the cached update status unless the tracked ref moved ──────────
from unit.part01 import SO  # noqa: E402

_tip54 = {"sha": "aaa1111", "moves": False}


def _fetch54():
    if _tip54["moves"]:
        _tip54["sha"] = "bbb2222"


def _git54(args, timeout=45):
    if args[:1] == ["rev-parse"]:
        return (_tip54["sha"] + "\n", "", 0) if _tip54["sha"] else ("", "", 1)
    return ("refs/remotes/origin/main\nrefs/remotes/origin/dev\n", "", 0)


_bt54 = []
with _patched():
    _patch(SO, "_is_git_checkout", lambda: True)
    _patch(SO, "_tracked_branch", lambda: "main")
    _patch(SO, "_fetch_all_branches", _fetch54)
    _patch(SO, "_update_in_progress", lambda: False)
    _patch(SO, "_git", _git54)
    _ts54_0 = SO._update_cache["ts"]
    try:
        for _moves54, _sha54 in ((False, "aaa1111"), (True, "aaa1111"), (False, "")):
            _tip54.update(moves=_moves54, sha=_sha54)
            SO._update_cache["ts"] = 12345.0
            SO.list_panel_branches()
            _bt54.append(SO._update_cache["ts"])
    finally:
        SO._update_cache["ts"] = _ts54_0
check("branch list: a fetch that did not move the tracked ref keeps the cached update status (no "
      "fresh GitHub walk on every host-page load); one that moved it, or an unreadable ref, drops it",
      _bt54 == [12345.0, 0.0, 0.0], repr(_bt54))

# ── A02: a restore and a self-update exclude each other across the windows #416 left open ──────
from panel.ops import backup as _bk54  # noqa: E402

_rx54_dir = _tf54.mkdtemp(prefix="lgsm-unit-p54-rx-")
with open(os.path.join(_rx54_dir, "install.sh"), "w", encoding="utf-8") as _fh54:
    _fh54.write("#!/bin/bash\n")
_rx54 = {"run": [], "restore_seen": [], "rc": 0}


def _run54(*a, **_k):
    """systemd-run, stood in: a restore asked for WHILE the launcher runs, then its exit code."""
    _rx54["run"].append(a)
    _rx54["restore_seen"].append(_bk54.restore_backup("p54.tar.gz"))
    return NS(returncode=_rx54["rc"], stderr="")


_launched54 = dict(SO._update_launched)
_disp54 = dict(_bk54._r12a_restore_dispatched)
try:
    with _patched():
        _patch(SO, "PANEL_DIR", _rx54_dir)
        _patch(SO, "_is_system_service", lambda: False)
        _patch(SO, "_helper_present", lambda: False)
        _patch(SO, "subprocess", NS(run=_run54, DEVNULL=-3, PIPE=-1))
        _patch(_bk54, "_restore_backup_locked", lambda *a, **k: (True, "restoring"))
        _bk54._r12a_restore_dispatched["ts"] = 0.0
        _rx54_up = SO._launch_installer(target_ref="", branch="main")
        _rx54_seen = list(_rx54["restore_seen"])
        SO._update_launched.update(ts=0.0, log="")
        _rx54["rc"], _rx54["run"], _rx54["restore_seen"] = 1, [], []
        _patch(_bk54, "_restore_backup_locked", lambda *a, **k: (False, "not restored"))
        _rx54_fail = SO._launch_installer(target_ref="", branch="main")
        _rx54_after_fail = SO._update_in_progress()
        _rx54["rc"], _rx54["run"] = 0, []
        _patch(SO, "_update_in_progress", lambda: False)
        _patch(_bk54, "_restore_backup_locked", lambda *a, **k: (True, "restoring"))
        _patch(_bk54, "DATA_DIR", _pl54.Path(_rx54_dir))
        _rx54_restore = _bk54.restore_backup("p54.tar.gz")
        _rx54_gone = SO._launch_installer(target_ref="", branch="main")   # no stage: swap done
        _rx54["run"] = []
        os.makedirs(os.path.join(_rx54_dir, ".restore-stage"))
        _rx54_swap = SO._launch_installer(target_ref="", branch="main")
finally:
    SO._update_launched.clear()
    SO._update_launched.update(_launched54)
    _bk54._r12a_restore_dispatched.update(_disp54)
    shutil.rmtree(_rx54_dir, ignore_errors=True)
check("restore vs update: a restore asked for while the self-update launcher is still starting is "
      "refused (the launch is recorded before the launcher runs, not after)",
      _rx54_up[0] is True and len(_rx54_seen) == 1 and _rx54_seen[0][0] is False
      and "update is being installed" in _rx54_seen[0][1], repr((_rx54_up, _rx54_seen)))
check("restore vs update: ...and a launch that failed takes its record back, so nothing waits on "
      "an update that never started", _rx54_fail[0] is False and _rx54_after_fail is False,
      repr((_rx54_fail, _rx54_after_fail)))
check("restore vs update: a self-update asked for after a restore was DISPATCHED (its lock released, "
      "the detached swap still to run) is refused",
      _rx54_restore[0] is True and _rx54_swap[0] is False and "restore is in progress" in _rx54_swap[1]
      and _rx54["run"] == [], repr((_rx54_restore, _rx54_swap, _rx54["run"])))
check("restore vs update: ...but once the swap has removed its staging directory the update goes "
      "ahead (no fixed wait after every restore)", _rx54_gone[0] is True, repr(_rx54_gone))
