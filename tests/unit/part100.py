"""Part 100 of the unit suite: Ubuntu's phased (deferred) updates are respected, never forced.

Owner, 2026-10-16: "sometimes Ubuntu defers updates... it will show that there's an update but when
you do the full-upgrade it won't install them... the panel needs to respect deferred updates just
in case there are issues." Held here:

* nothing the panel runs forces a phased update: APT::Get::Always-Include-Phased-Updates appears
  nowhere in panel/, tools/, app.py or install.sh, and apt-full-upgrade takes no "phased" choice;
* the OS-update check reads apt's own upgrade simulation: held back = what `apt list` lists minus
  the simulation's Inst lines, by name and architecture — the measured 24.04 output, 22.04's apt
  2.4 with no phasing heading, apt.conf's Output-Version and Show-Versions, i386 against amd64,
  [all] — and an unread simulation counts every package, as before, saying the split is unknown;
  it runs only when the list read found packages;
* the read is in the C locale on the panel host and on a remote;
* held-back packages are not counted: a host with only those raises no banner and no alert, and
  the OS Updates card lists them apart under "held back by apt";
* no page request runs apt: the panel host's pages read the update check's cache.

HOW IT RUNS. Pure functions; a real bash over this part's own stand-in programs; part12's Flask
app and client with every host call stubbed through _p9_patch; node for the card.
"""
import importlib.machinery as _ilm100
import importlib.util as _ilu100
import json as _json100
import os
import shutil as _shutil100
import subprocess as _sp100  # nosec B404 - runs bash on the panel's own command text
import tempfile as _tf100
import types as _types100

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, P9_HOST, P9_LOCAL, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json,
                         _p9_patch, _p9_restore_all)
from unit.part47 import _cut47, _node47
from panel.core import panel_state as _ps100
from panel.db.models import RemoteServer as _RS100, db as _db100
from panel.ops import system_ops as _so100
from panel.ops.ssh_manager import _core as _smc100
from panel.ops.ssh_manager import hosts as _smh100
from panel.routes import os_updates as _osu100
from panel.security import privileged as _priv100

NS = _types100.SimpleNamespace
_TRIP100_START = len(_P9_TRIPPED)
_TMP100 = os.path.realpath(_tf100.mkdtemp(prefix="lgsm-unit-p100-"))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. Nothing forces a phased update
# ════════════════════════════════════════════════════════════════════════════════════════════════
_FORCE100 = "Always-Include-" + "Phased-Updates"   # split, so this file is not its own hit


def _force_hits100(paths):
    """'file:line' for every line under `paths` (files or trees) that names the forcing option."""
    hits = []
    for top in paths:
        full = os.path.join(_root, top)
        files = [full] if os.path.isfile(full) else [
            os.path.join(d, f) for d, _dirs, fs in os.walk(full) for f in fs]
        for path in files:
            try:
                with open(path, encoding="utf-8") as fh:
                    lines = fh.read().splitlines()
            except (UnicodeDecodeError, OSError):
                continue          # a binary file holds no apt command line
            hits += ["%s:%d" % (path, n)
                     for n, line in enumerate(lines, 1) if _FORCE100 in line]
    return hits


_hits100 = _force_hits100(["panel", "tools", "app.py", "install.sh"])
_ctl100 = os.path.join(_TMP100, "ctl")
os.makedirs(_ctl100)
with open(os.path.join(_ctl100, "x.py"), "w", encoding="utf-8") as _fh100:
    _fh100.write("argv = ['-o', 'APT::Get::%s=true']\n" % _FORCE100)
check("phased updates: no file in panel/, tools/, app.py or install.sh forces them "
      "(APT::Get::Always-Include-Phased-Updates was passed by the remote OS-update job, the helper's "
      "and apt-full-upgrade's \"phased\" choice — defeating the rollout that holds back a bad update)",
      _hits100 == [], repr(_hits100))
check("phased updates: ...and the scan finds the option when a file does carry it (control)",
      _force_hits100([_ctl100]) != [])

_helper_spec100 = _ilu100.spec_from_loader(
    "p100_helper", _ilm100.SourceFileLoader("p100_helper", os.path.join(_root, "tools", "panel-helper")))
_helper100 = _ilu100.module_from_spec(_helper_spec100)
_helper_spec100.loader.exec_module(_helper100)


def _refused100(fn, *a):
    """Whether `fn(*a)` raises (a refused argument list)."""
    try:
        fn(*a)
    except Exception:
        return True
    return False


_argv100 = _priv100._ARGV["apt-full-upgrade"][1]([])
_hargv100 = _helper100.VERBS["apt-full-upgrade"][1]([])
check("phased updates: apt-full-upgrade takes no \"phased\" choice on either side — the panel's verb "
      "table and the helper's refuse it, and the upgrade they run is apt's own set",
      _refused100(_priv100.check_args, "apt-full-upgrade", ["phased"])
      and _refused100(_helper100.validate, "apt-full-upgrade", ["phased"])
      and _priv100.check_args("apt-full-upgrade", []) == []
      and not _refused100(_helper100.validate, "apt-full-upgrade", [])
      and all(_FORCE100 not in " ".join(v) and "full-upgrade" in v for v in (_argv100, _hargv100)),
      repr((_argv100, _hargv100)))
_job100 = _priv100._REMOTE_ACTIONS["os-update-run"]([])
check("phased updates: ...and the remote's detached OS-update job does not force them either",
      _FORCE100 not in _job100 and "full-upgrade" in _job100, _job100[:300])

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. Reading the simulation: held back = what `apt list` lists minus apt's Inst lines
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The upgradable list as measured on the test VPS (Ubuntu 24.04.5, apt 2.8.3), with curl standing
# for the updates an upgrade does install (the security one the banner checks below count).
_LIST100 = (
    "Listing...\n"
    "apparmor/noble-updates 4.0.1really4.0.1-0ubuntu0.24.04.5 amd64 "
    "[upgradable from: 4.0.1really4.0.1-0ubuntu0.24.04.4]\n"
    "curl/noble-security 8.5.0-2ubuntu10.7 amd64 [upgradable from: 8.5.0-2ubuntu10.6]\n"
    "libapparmor1/noble-updates 4.0.1really4.0.1-0ubuntu0.24.04.5 amd64 "
    "[upgradable from: 4.0.1really4.0.1-0ubuntu0.24.04.4]\n"
    "libapparmor1/noble-updates 4.0.1really4.0.1-0ubuntu0.24.04.5 i386 "
    "[upgradable from: 4.0.1really4.0.1-0ubuntu0.24.04.4]\n"
    "snapd/noble-updates 2.68.5+ubuntu24.04.1 amd64 [upgradable from: 2.67.1+24.04]")
_INST_CURL100 = "Inst curl [8.5.0-2ubuntu10.6] (8.5.0-2ubuntu10.7 Ubuntu:24.04/noble-security [amd64])"
_CONF_CURL100 = "Conf curl (8.5.0-2ubuntu10.7 Ubuntu:24.04/noble-security [amd64])"
_SIM_HEAD100 = ("R27P-ARCH amd64\n"
                "NOTE: This is only a simulation!\n"
                "      apt-get needs root privileges for real execution.\n"
                "Reading package lists...\n"
                "Calculating upgrade...\n")
# apt 2.8 (24.04, measured): the phased ones under their own heading.
_SIM_28_100 = (_SIM_HEAD100
               + "The following upgrades have been deferred due to phasing:\n"
               "  apparmor libapparmor1\n"
               "  libapparmor1:i386 snapd\n"
               "The following packages will be upgraded:\n"
               "  curl\n"
               "1 upgraded, 0 newly installed, 0 to remove and 4 not upgraded.\n"
               + _INST_CURL100 + "\n" + _CONF_CURL100)
# apt 2.4 (22.04): no phasing heading at all — the phased ones are only "kept back", and absent
# from the Inst lines. This is the host the heading-reading version announced updates on forever.
_SIM_24_100 = (_SIM_HEAD100
               + "The following packages have been kept back:\n"
               "  apparmor libapparmor1 libapparmor1:i386 snapd\n"
               "The following packages will be upgraded:\n"
               "  curl\n"
               "1 upgraded, 0 newly installed, 0 to remove and 4 not upgraded.\n"
               + _INST_CURL100 + "\n" + _CONF_CURL100)
# APT::Output-Version=30 in apt.conf: apt's short headings.
_SIM_30_100 = (_SIM_HEAD100
               + "Not upgrading yet due to phasing:\n"
               "  apparmor  libapparmor1  libapparmor1:i386  snapd\n"
               "Upgrading:\n"
               "  curl\n"
               "Summary:\n"
               "  Upgrading: 1, Installing: 0, Removing: 0, Not Upgrading: 4\n"
               + _INST_CURL100 + "\n" + _CONF_CURL100)
# APT::Get::Show-Versions=true in apt.conf: one package a line, with "(old => new)" — tokens the
# heading reader took for package names.
_SIM_SV100 = (_SIM_HEAD100
              + "The following upgrades have been deferred due to phasing:\n"
              "   apparmor (4.0.1really4.0.1-0ubuntu0.24.04.4 => 4.0.1really4.0.1-0ubuntu0.24.04.5)\n"
              "   libapparmor1 (4.0.1really4.0.1-0ubuntu0.24.04.4 => 4.0.1really4.0.1-0ubuntu0.24.04.5)\n"
              "   libapparmor1:i386 (4.0.1really4.0.1-0ubuntu0.24.04.4 => 4.0.1really4.0.1-0ubuntu0.24.04.5)\n"
              "   snapd (2.67.1+24.04 => 2.68.5+ubuntu24.04.1)\n"
              "The following packages will be upgraded:\n"
              "   curl (8.5.0-2ubuntu10.6 => 8.5.0-2ubuntu10.7)\n"
              "1 upgraded, 0 newly installed, 0 to remove and 4 not upgraded.\n"
              + _INST_CURL100 + "\n" + _CONF_CURL100)
_HELD100 = [("apparmor", "amd64"), ("libapparmor1", "amd64"), ("libapparmor1", "i386"),
            ("snapd", "amd64")]


def _result100(sim, list_out=_LIST100, rc=0, list_rc=0):
    """r27p_updates_result over `list_out` with the simulation answering (sim, rc)."""
    return _so100.r27p_updates_result(list_out, list_rc, lambda: (sim, rc))


def _held_of100(res):
    """The (name, arch) pairs a result holds back, sorted."""
    return sorted((p["name"], p["arch"]) for p in res["deferred"])


_res100 = _result100(_SIM_28_100)
check("held back: the measured apt 2.8 output — apparmor, libapparmor1 (both archs) and snapd have "
      "no Inst line and are held back, curl is what an upgrade installs now and the only one counted",
      _res100["ok"] and _res100["count"] == 1 and [p["name"] for p in _res100["packages"]] == ["curl"]
      and _held_of100(_res100) == _HELD100
      and _res100["deferred_known"] is True and _res100["updates_available"] is True,
      repr(_res100))
_shapes100 = {k: _result100(v) for k, v in (("apt 2.4", _SIM_24_100), ("Output-Version 30", _SIM_30_100),
                                             ("Show-Versions", _SIM_SV100))}
check("held back: 22.04's apt 2.4, which prints no \"deferred due to phasing\" heading (the phased "
      "ones are only absent from the Inst lines), holds back the same four and counts curl alone — "
      "and so does an apt.conf with APT::Output-Version=30's short headings",
      all(_held_of100(_shapes100[k]) == _HELD100 and _shapes100[k]["count"] == 1
          and _shapes100[k]["deferred_known"] is True for k in ("apt 2.4", "Output-Version 30")),
      repr(_shapes100))
check("held back: APT::Get::Show-Versions=true's \"name (old => new)\" lines add no rows — every "
      "held-back entry is one `apt list` listed, never \"(4.0.1-4\" or \"=>\"",
      _held_of100(_shapes100["Show-Versions"]) == _HELD100
      and _shapes100["Show-Versions"]["count"] == 1, repr(_shapes100["Show-Versions"]))
check("held back: Inst lines are read by name and architecture, from the candidate's [arch]",
      _so100.parse_inst(_SIM_28_100) == {("curl", "amd64")}
      and _so100.parse_inst("R27P-ARCH amd64\n"
                            "Inst libapparmor1:i386 [4.0.1-4] (4.0.1-5 Ubuntu:24.04/noble-updates [i386])\n"
                            "Inst tzdata [2024a-0] (2024b-0 Ubuntu:24.04/noble-updates [all]) []\n"
                            "Inst bash [5.2-1]\n")
      == {("libapparmor1", "i386"), ("tzdata", "all"), ("bash", "amd64")},
      repr(_so100.parse_inst(_SIM_28_100)))
check("held back: a line that is not a simulation Inst line is never read as one",
      _so100.parse_inst("R27P-ARCH amd64\nInst\nInst Bad_Name [1] (2 x [amd64])\n"
                        "  Inst curl [1] (2 x [amd64])\nInstall curl\nConf curl (2 x [amd64])\n"
                        "Inst curl:BAD [1] (2 x [amd64])\n") == set())
_i386_100 = _result100(_SIM_HEAD100 + "Inst libapparmor1:i386 [4.0.1really4.0.1-0ubuntu0.24.04.4] "
                       "(4.0.1really4.0.1-0ubuntu0.24.04.5 Ubuntu:24.04/noble-updates [i386])\n")
_amd64_100 = _result100(_SIM_HEAD100 + "Inst libapparmor1 [4.0.1really4.0.1-0ubuntu0.24.04.4] "
                        "(4.0.1really4.0.1-0ubuntu0.24.04.5 Ubuntu:24.04/noble-updates [amd64])\n")
check("held back: libapparmor1's i386 Inst line installs the i386 build only — the amd64 build, with "
      "no Inst line of its own, is held back",
      [(p["name"], p["arch"]) for p in _i386_100["packages"]] == [("libapparmor1", "i386")]
      and ("libapparmor1", "amd64") in _held_of100(_i386_100), repr(_i386_100))
check("held back: ...and the amd64 Inst line installs the amd64 build only",
      [(p["name"], p["arch"]) for p in _amd64_100["packages"]] == [("libapparmor1", "amd64")]
      and ("libapparmor1", "i386") in _held_of100(_amd64_100), repr(_amd64_100))
_bare100 = _result100(_SIM_HEAD100 + "Inst snapd [2.67.1+24.04] (2.68.5+ubuntu24.04.1 Ubuntu:24.04/noble-updates)\n")
check("held back: an Inst line with no [arch] is the native build's (the probe's R27P-ARCH line)",
      [(p["name"], p["arch"]) for p in _bare100["packages"]] == [("snapd", "amd64")], repr(_bare100))
_ALL_LIST100 = ("Listing...\n"
                "tzdata/noble-updates 2024b-0ubuntu0.24.04.1 all [upgradable from: 2024a-0ubuntu1]\n"
                "fonts-x/noble-updates 2.0-1 amd64 [upgradable from: 1.0-1]\n"
                "libx/noble-updates 2.0-1 amd64 [upgradable from: 1.0-1]\n"
                "libx/noble-updates 2.0-1 i386 [upgradable from: 1.0-1]")
_all100 = _result100(_SIM_HEAD100
                     + "Inst tzdata [2024a-0ubuntu1] (2024b-0ubuntu0.24.04.1 Ubuntu:24.04/noble-updates [all])\n"
                     "Inst fonts-x [1.0-1] (2.0-1 Ubuntu:24.04/noble-updates [all])\n"
                     "Inst libx [1.0-1] (2.0-1 Ubuntu:24.04/noble-updates [all])\n", list_out=_ALL_LIST100)
check("held back: an [all] Inst line matches the one `apt list` entry of that name (tzdata is \"all\" "
      "in both, fonts-x became Architecture: all) — but not a name listed for two architectures",
      sorted((p["name"], p["arch"]) for p in _all100["packages"]) == [("fonts-x", "amd64"), ("tzdata", "all")]
      and _held_of100(_all100) == [("libx", "amd64"), ("libx", "i386")], repr(_all100))
_only100 = _result100(_SIM_28_100, list_out="Listing...\n" + "\n".join(
    _LIST100.splitlines()[i] for i in (1, 3, 4, 5)))
check("held back: a host whose only updates are held back counts none (nothing an upgrade would "
      "install), and still lists them",
      _only100["count"] == 0 and _only100["updates_available"] is False
      and len(_only100["deferred"]) == 4, repr(_only100))
_extra100 = _result100(_SIM_28_100 + "\nInst linux-image-6.8.0-99-generic (6.8.0-99.99 Ubuntu:24.04/noble-updates [amd64])")
check("held back: an Inst line for a NEW package (a dependency `apt list` does not list) adds no row",
      _extra100["count"] == 1 and _held_of100(_extra100) == _HELD100, repr(_extra100))
_unread100 = [_result100(_SIM_28_100, rc=100), _result100(""),
              _result100(_SIM_28_100.split("\n", 1)[1])]
check("held back: a simulation that failed, said nothing or lost its arch line is UNKNOWN, never "
      "\"an upgrade installs nothing\" (which would hold every update back): every package stays "
      "counted, as before",
      all(r["count"] == 5 and r["deferred"] == [] and r["deferred_known"] is False for r in _unread100),
      repr(_unread100))
_asked100 = []


def _probe_counted100():
    """The simulation, recording that it was asked."""
    _asked100.append(1)
    return _SIM_28_100, 0


_fail100 = _so100.r27p_updates_result("", -1, _probe_counted100)
_failed_with_out100 = _so100.r27p_updates_result(_LIST100, 100, _probe_counted100)
_clean100 = _so100.r27p_updates_result("Listing...\n", 0, _probe_counted100)
check("held back: the simulation is not run when the list read failed or found nothing — a hung "
      "host does not wait out a second apt command, an up-to-date one does not pay ~2.4 s for one",
      _asked100 == [] and _fail100["ok"] is False and _fail100["deferred_known"] is False
      and _failed_with_out100["ok"] is False and _failed_with_out100["deferred_known"] is False
      and _clean100["ok"] and _clean100["count"] == 0 and _clean100["deferred"] == []
      and _clean100["deferred_known"] is True, repr((_asked100, _fail100, _clean100)))
_result100(_SIM_28_100)
_so100.r27p_updates_result(_LIST100, 0, _probe_counted100)
check("held back: ...and it is run when the list read found packages (control)", _asked100 == [1])

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. A German host: the read runs in the C locale, on the panel host and on a remote
# ════════════════════════════════════════════════════════════════════════════════════════════════
_BIN100 = os.path.join(_TMP100, "bin")
os.makedirs(_BIN100)
_GETTEXT100 = ('loc="${LC_ALL:-${LC_MESSAGES:-$LANG}}"; '
               'case "$loc" in C|C.*|POSIX) de=0 ;; *) case "${LANGUAGE:-$loc}" in de*) de=1 ;; *) de=0 ;; esac ;; esac; ')
_STANDINS100 = {
    "apt": "printf '%s\\n' " + " ".join("'%s'" % ln for ln in _LIST100.splitlines()),
    "dpkg": "echo amd64",
    # apt's de catalog renders the headings in German; the Inst lines are the same in every language.
    "apt-get": _GETTEXT100 + (
        'if [ "$de" = 1 ]; then echo "Die folgenden Pakete werden aktualisiert (Upgrade):"; '
        'else echo "The following packages will be upgraded:"; fi; echo "  curl"; '
        "echo '" + _INST_CURL100 + "'"),
}
for _name100, _body100 in _STANDINS100.items():
    _path100 = os.path.join(_BIN100, _name100)
    with open(_path100, "w", encoding="utf-8") as _fh100:
        _fh100.write("#!/bin/bash\n" + _body100 + "\n")
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stand-in program this part runs
    os.chmod(_path100, 0o700)
_GERMAN100 = {"PATH": _BIN100 + ":/usr/bin:/bin", "LANG": "de_DE.UTF-8", "LANGUAGE": "de_DE:de",
              "HOME": _TMP100}
_cmds100 = []


def _bash100(command, *_a, **_k):
    """(out, err, rc) of `command` in a real bash on the German host; records the command."""
    _cmds100.append(command)
    r = _sp100.run(["/bin/bash", "-c", command],  # nosec B603 - bash on this repo's own command text
                   env=_GERMAN100, capture_output=True, text=True, timeout=30, check=False)
    return r.stdout.strip(), r.stderr.strip(), r.returncode


_ger100 = {}
try:
    _p9_arm(who="part100")
    _p9_patch(_so100, "_run", _bash100)
    _ger100["local"] = _so100.os_update_available(refresh=False)
    _p9_patch(_smc100, "run_privileged", lambda *a, **k: ("", "", 0))
    _p9_patch(_smc100, "run_command", lambda _s, command, *a, **k: _bash100(command))
    _ger100["remote"] = _smh100.remote_os_check_updates(NS(id=-100, name="p100"))

    def _probe_raises100(_s, command, *a, **k):
        """The list read answers; the upgrade simulation raises, as paramiko does on a dropped link."""
        if "apt-get -s" in command:
            raise ConnectionError("unit p100: link dropped")
        return _LIST100, "", 0
    _p9_patch(_smc100, "run_command", _probe_raises100)
    try:
        _ger100["raised"] = _smh100.remote_os_check_updates(NS(id=-100, name="p100"))
    except Exception as exc:          # the check below names it
        _ger100["raised"] = repr(exc)
finally:
    _p9_restore_all()
check("held back: on a German host the simulation is read, on the panel host and on a remote, and "
      "the same four are held back",
      all(_held_of100(_ger100.get(k) or {"deferred": []}) == _HELD100
          and _ger100[k]["count"] == 1 and _ger100[k]["deferred_known"] is True
          for k in ("local", "remote")), repr(_ger100))
_rz100 = _ger100.get("raised")
check("held back: a remote whose upgrade simulation RAISES after the list was read keeps the list, "
      "every package counted, and the split unknown — not a failed check",
      isinstance(_rz100, dict) and _rz100["ok"] and _rz100["count"] == 5
      and _rz100["deferred_known"] is False, repr(_rz100))
_probe100 = _smc100._R19A_C_LOCALE + _smh100._R27P_UPGRADE_SIM
check("held back: the panel host's literal probe is _core's C-locale prefix plus the remote's "
      "probe, character for character",
      _probe100 in _cmds100 and _cmds100.count(_probe100) == 2, repr(_cmds100))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. Not counted: no banner, no alert, and the card lists them apart
# ════════════════════════════════════════════════════════════════════════════════════════════════
_seen_was100 = dict(_ps100._os_update_seen)
_hosts_was100 = dict(_ps100._os_update_state["hosts"])
_ban100, _told100 = {}, []
try:
    _p9_arm(who="part100")
    _p9_patch(_osu100.notifications, "notify", lambda *a, **k: _told100.append(a))
    with _p9.app_context():
        _row100 = _db100.session.get(_RS100, P9_HOST)
        for _k100, _got100 in (("deferred-only", _only100), ("mixed", _res100)):
            _ps100._os_update_seen.clear()
            _ps100._os_update_state["hosts"][P9_HOST] = (0, 0)   # read before: not a first read
            _told100.clear()
            _osu100._record_and_announce(_row100, _got100, False)
            _ban100[_k100] = {
                "summary": [(h["id"], h["count"]) for h in _p9_json(
                    _p9_client(P9_ADMIN).get("/api/os-updates/summary")).get("hosts", [])],
                "cached": _p9_json(_p9_client(P9_ADMIN).get("/api/remote/%d/updates-cached" % P9_HOST)),
                "told": list(_told100)}
finally:
    _p9_restore_all()
    _ps100._os_update_seen.clear()
    _ps100._os_update_seen.update(_seen_was100)
    _ps100._os_update_state["hosts"].clear()
    _ps100._os_update_state["hosts"].update(_hosts_was100)
_do100, _mx100 = _ban100.get("deferred-only") or {}, _ban100.get("mixed") or {}
check("phased updates: a host whose only updates are deferred raises no banner and no alert",
      _do100.get("summary") == [] and _do100.get("told") == [], repr(_do100))
check("phased updates: ...its card still gets them, apart, with a count of 0",
      (_do100.get("cached") or {}).get("count") == 0
      and len((_do100.get("cached") or {}).get("deferred") or []) == 4
      and (_do100.get("cached") or {}).get("deferred_known") is True, repr(_do100.get("cached")))
check("phased updates: a host with one real update and four deferred is announced as ONE, in the "
      "banner and the alert",
      _mx100.get("summary") == [(P9_HOST, 1)] and len(_mx100.get("told") or []) == 1
      and "1 security update of 1 waiting" in repr(_mx100.get("told")), repr(_mx100))

_RMJ100 = open(os.path.join(_root, "static", "js", "remote_manage.js"), encoding="utf-8").read()


def _cut_or100(head):
    """_cut47's statement, or a comment naming it, so the check that runs it fails BY NAME."""
    return _cut47(_RMJ100, head) if head in _RMJ100 else "/* MISSING %s */" % head


_name100 = "OS Updates card: deferred updates listed apart"
_prog100 = (
    "const els = {'update-info': {innerHTML: ''}, 'btn-install-updates': {disabled: false, title: ''}};\n"
    "global.document = {getElementById: id => els[id] || null};\n"
    "function escapeHtml(s){ return String(s).replace(/</g, '&lt;'); }\n"
    + "".join(_cut_or100(h) + "\n" for h in (
        "function isSecurityPkg(", "function renderUpdates(", "function renderDeferred(",
        "function setInstallUpdatesState("))
    + "const out = {};\n"
    "for (const [k, d] of Object.entries(" + _json100.dumps({
        "only": dict(_only100), "mixed": dict(_res100), "unknown": dict(_unread100[0])}) + ")) {\n"
    "  renderUpdates(d, '');\n"
    "  out[k] = {html: els['update-info'].innerHTML, off: els['btn-install-updates'].disabled}; }\n"
    "console.log(JSON.stringify(out));\n")
_card100 = _node47(_prog100)
if _card100 is None:
    skip(_name100, "node is not installed here")
else:
    _held100 = "Held back by apt (Ubuntu's phased rollout, or kept back)"
    _o100, _m100, _u100 = (_card100.get(k) or {} for k in ("only", "mixed", "unknown"))
    check(_name100 + ": deferred-only reads \"up to date\" with Install disabled, and lists the four "
          "under the held-back note",
          "System is up to date." in _o100.get("html", "") and _o100.get("off") is True
          and _held100 in _o100.get("html", "") and "libapparmor1 (i386)" in _o100.get("html", "")
          and "snapd" in _o100.get("html", ""), repr(_card100)[:600])
    check(_name100 + ": mixed reads \"1 update available\" with Install enabled, the deferred four "
          "below it",
          "1 <span>update available</span>" in _m100.get("html", "") and _m100.get("off") is False
          and _held100 in _m100.get("html", "")
          and _m100.get("html", "").index("curl") < _m100.get("html", "").index(_held100),
          repr(_card100)[:600])
    check(_name100 + ": an unread simulation keeps every package counted and says the split is unknown",
          "5 <span>updates available</span>" in _u100.get("html", "")
          and "apt is holding back" in _u100.get("html", "")
          and _held100 not in _u100.get("html", ""), repr(_card100)[:600])

_cat100 = {}
for _L100 in ("es", "fr"):
    _cat100[_L100] = {}
    for _f100 in os.listdir(os.path.join(_root, "translations", _L100)):
        with open(os.path.join(_root, "translations", _L100, _f100), encoding="utf-8") as _fh100:
            _cat100[_L100].update(_json100.load(_fh100))
_new100 = ["Held back by apt (Ubuntu's phased rollout, or kept back) — an upgrade does not install these yet.",
           "Couldn't read which of these apt is holding back."]
check("phased updates: the card's two new sentences are in the es and fr catalogs, and spelled in "
      "remote_manage.js exactly as catalogued",
      all(s in _cat100[L] for s in _new100 for L in ("es", "fr"))
      and all(_json100.dumps(s, ensure_ascii=False) in _RMJ100 for s in _new100),
      repr([(L, s) for L in ("es", "fr") for s in _new100 if s not in _cat100[L]]))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. No apt on a page request: the panel host's pages read the update check's cache
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The check now simulates the upgrade too (2.36 s measured on the test VPS). get_server_status ran
# the check's list read on every cold render of the panel host's page, and the simulation with it,
# so every visit past its 15 s cache waited ~2.4 s more. Every way system_ops reaches a command is
# recorded; a cold render of each page, and the JSON the page polls, must name apt in none.
_page_cmds100 = []


def _rec100(kind):
    """A stand-in for one command path: records what it was asked, answers like apt."""
    def _answer(*a, **_k):
        text = " ".join(str(x) for x in a[:2])
        _page_cmds100.append((kind, text))
        if "apt list --upgradable" in text:
            return _LIST100, "", 0
        return (_SIM_28_100 if "apt-get -s" in text else ""), "", 0
    return _answer


_pages100, _ctlp100 = {}, {}
_sudo_was100 = dict(_so100._SUDO_PROBE)
try:
    _p9_arm(who="part100")
    for _n100 in ("_run", "_run_verb", "_git"):
        _p9_patch(_so100, _n100, _rec100("system_ops." + _n100))
    _p9_patch(_smc100, "run_command", _rec100("ssh_manager.run_command"))
    _p9_patch(_smc100, "run_privileged", _rec100("ssh_manager.run_privileged"))
    for _url100 in ("/server-management", "/remote/%d/manage" % P9_LOCAL, "/api/server-management"):
        _so100._status_cache["data"] = None          # cold: past the 15 s cache
        _so100._SUDO_PROBE["at"] = 0.0
        del _page_cmds100[:]
        _code100 = _p9_client(P9_ADMIN).get(_url100).status_code
        _pages100[_url100] = (_code100, [c for c in _page_cmds100 if "apt" in c[1]],
                              len(_page_cmds100))
    # Control: the same recorders see the Check button's apt reads, simulation included.
    del _page_cmds100[:]
    _ctlp100["check"] = _p9_json(_p9_client(P9_ADMIN).get("/api/remote/%d/check-updates" % P9_LOCAL))
    _ctlp100["cmds"] = [c[1] for c in _page_cmds100]
finally:
    _p9_restore_all()
    _so100._status_cache["data"] = None
    _so100._SUDO_PROBE.update(_sudo_was100)
    _ps100._os_update_seen.pop(P9_LOCAL, None)
check("held back: a cold render of /server-management, /remote/<panel host>/manage and "
      "/api/server-management runs no apt command (the update check's simulation took ~2.4 s on "
      "every page load past the 15 s status cache)",
      all(v[0] == 200 and v[1] == [] for v in _pages100.values()) and len(_pages100) == 3,
      repr(_pages100))
check("held back: ...while the renders did reach the recorders (ufw, Tailscale) — the gate saw them",
      all(v[2] > 0 for v in _pages100.values()), repr(_pages100))
check("held back: ...and the Check button's update check does run the list read and the simulation, "
      "and answers with the split (control)",
      any("apt list --upgradable" in c for c in _ctlp100.get("cmds", []))
      and any("apt-get -s" in c for c in _ctlp100.get("cmds", []))
      and (_ctlp100.get("check") or {}).get("count") == 1
      and len((_ctlp100.get("check") or {}).get("deferred") or []) == 4,
      repr(_ctlp100)[:600])

_shutil100.rmtree(_TMP100, ignore_errors=True)
check("part100: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP100_START, repr(_P9_TRIPPED[_TRIP100_START:][:6]))
