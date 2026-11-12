r"""Part 178 of the unit suite: review 1109's integration fixes.

* OWNER RULE: an SSH port move on a host whose IPv4 SSH is public, whose firewall lists no `(v6)` row,
  and whose ufw files (/etc/default/ufw) could not be read is refused, naming what to add. It was judged
  as IPv4 alone, and the public path's `allow proto tcp to any port N` opens both families on a host with
  IPv6 on, so the new port went public over IPv6 where SSH was not. It goes on where it adds nothing
  that could open IPv6: the new port already public over IPv4, or a default incoming allow policy.
  Driven through change_ssh_port on part159's stand-in and through the SSH port route on part12's app.
* LinuxGSM v26.6.0 dropped btl and onset from serverlist.csv: the panel's cap table is empty and no
  panel source names either game.
* The complexity gate stops when git's diff fails: a base the checkout lacks listed no changed file,
  and the gate passed having judged nothing.

HOW IT RUNS. part159's port-move stand-in and part163's stored-file patch on part12's patcher with its
transport tripwire armed; the gate on part28's throwaway repositories. Nothing reaches a host, sudo,
ufw, a resolver or data/.
"""
import os
import re as _re178
import shutil as _sh178
import subprocess as _sp178  # nosec B404 - git on a throwaway repository, fixed argv
import tempfile as _tf178

from unit.part01 import check
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9_arm, _p9_audit, _p9_client, _p9_core, _p9_json,
                         _p9_patch, _p9_restore_all)
from unit.part28 import _GIT28, _cx28
from unit.part159 import _Box159, _PUB_SESS159, _V4_ADD159, _move159
from unit.part163 import _BOTH163, _DENY_OTHER163, _PROXY_ADD163, _PUB22_163, _STORED_TEXT163, _move163
from panel.ops.ssh_manager import firewall as _fw178, hosts as _hosts178, ufweval as _ue178
from panel.services import lgsm_data as _lgsm178
from panel.ops.ssh_manager import game as _game178

_TRIP178_START = len(_P9_TRIPPED)
_UNREAD178 = "could not be read, so whether a rule for port 2022 would also open it over IPv6 is not known"

# ════════════════════════════════════════════════════════════════════════════════════════════════
# OWNER RULE: ufw's files unread, IPv4 SSH public, no (v6) row -> refused, nothing sent
# ════════════════════════════════════════════════════════════════════════════════════════════════
_refused178 = {
    "a remote, IPv4 public SSH": _move163([_PUB22_163], ipv6=None),
    "a remote, a LIMIT": _move163(["22/tcp  LIMIT IN  Anywhere"], ipv6=None),
    "the panel's host": _move163([_PUB22_163], None, ipv6=None, local=True),
}
check("1109 finding 4 (OWNER RULE): an SSH port move where IPv4 SSH is public, no (v6) row is listed and ufw's "
      "files could not be read is refused, naming the IPv4 rule to add, with nothing sent (%s): judged as IPv4 "
      "alone, the public path's both-family allow opened the new port over IPv6 on a host with IPv6 on"
      % ", ".join(_refused178),
      all(r[0] is False and r[2] == [] and _UNREAD178 in r[1] and "Nothing was changed" in r[1]
          and "ufw allow from 0.0.0.0/0 to any port 2022 proto tcp" in r[1] for r in _refused178.values()),
      repr({k: (r[0], r[1][:240], r[2]) for k, r in _refused178.items()}))


def _hosts_move178(rules, text):
    """_move159 with ufw's stored files read as `text`."""
    _p9_patch(_fw178, "_fwa_read_stored", lambda server: _fw178._fwa_split_stored(text))
    return _move159(rules)


_noline178 = _hosts_move178([_PUB22_163], _STORED_TEXT163.replace("IPV6=yes\n", ""))
check("1109 finding 4: ...and so is one whose ufw file was read but says neither IPV6=yes nor IPV6=no (not known "
      "is never a reason to add a rule that may open IPv6)",
      _noline178[0] is False and _noline178[2] == [] and _UNREAD178 in _noline178[1], repr(_noline178))


def _move_policy178(rules, allow_in):
    """_move163 with the files unread and `ufw status verbose`'s default incoming policy read as allow or not."""
    _p9_patch(_fw178, "remote_ufw_default_allows_in", lambda server: allow_in)
    return _move163(rules, ipv6=None)


_goes178 = {
    "the new port already public over IPv4": _move163([_PUB22_163, "2022/tcp  ALLOW IN  Anywhere"], ipv6=None),
    "a default incoming allow policy": _move_policy178([_PUB22_163], True),
}
check("1109 finding 4: ...while with the files unread the move goes on where it adds nothing that could open IPv6: "
      "the new port already let in over IPv4 (nothing added), or a default incoming allow (every port is public "
      "in both families already: the public path)",
      _goes178["the new port already public over IPv4"][0] is True
      and _goes178["the new port already public over IPv4"][2] == []
      and _goes178["a default incoming allow policy"][0] is True
      and _goes178["a default incoming allow policy"][2] == _PROXY_ADD163,
      repr({k: (r[0], r[1][:200], r[2]) for k, r in _goes178.items()}))
# Under a default incoming ALLOW, a DENY for one public address above the public rule still holds: SSH
# was refused there, and the allow policy would let the new port in on that address the moment SSH moves.
_deny_allow178 = _move_policy178([_DENY_OTHER163] + _BOTH163, True)
check("1109 adversarial M1: under a default incoming allow, a DENY for one public address above the public "
      "rule refuses the move naming it and adds nothing, as under a default deny",
      _deny_allow178[0] is False and _deny_allow178[2] == [] and _DENY_OTHER163 in _deny_allow178[1],
      repr((_deny_allow178[0], _deny_allow178[1][:300], _deny_allow178[2])))
_read_ok178 = {"IPV6=yes": _move163([_PUB22_163], ipv6="yes"), "IPV6=no": _move163([_PUB22_163], ipv6="no"),
               "a (v6) row listed": _move163([_PUB22_163, "22/tcp (v6)  ALLOW IN  Anywhere (v6)"], ipv6=None)}
check("1109 finding 4: ...and files that read decide as before: IPV6=yes gets IPv4's rule from anywhere alone, "
      "IPV6=no the public path, and a listed (v6) row never needs the files (controls)",
      _read_ok178["IPV6=yes"][0] is True and _read_ok178["IPV6=yes"][2] == _V4_ADD159
      and _read_ok178["IPV6=no"][0] is True and _read_ok178["IPV6=no"][2] == _PROXY_ADD163
      and _read_ok178["a (v6) row listed"][0] is True and _read_ok178["a (v6) row listed"][2] == _PROXY_ADD163,
      repr({k: (r[0], r[1][:200], r[2]) for k, r in _read_ok178.items()}))


def _route_move178(rules):
    """POST /api/remote/<P9_HOST>/ssh-port {port: 2022} over part159's stand-in, ufw's files unread.

    -> (status, json, the allow verbs sent, the newest change_ssh_port audit row).
    """
    box = _Box159(rules)
    try:
        _p9_arm(who="part178")
        _p9_patch(_p9_core, "run_privileged", box.priv)
        _p9_patch(_p9_core, "run_command", lambda *a, **k: ("", "", 1))
        _p9_patch(_p9_core, "write_root_file", box.write)
        _p9_patch(_hosts178, "_sshd_socket_activated", lambda s: False)
        _p9_patch(_hosts178, "_restart_ssh_listener", box.restart)
        _p9_patch(_hosts178, "_point_f2b_sshd_at", lambda server, ports: ("updated", ""))
        _p9_patch(_hosts178, "_fwb_ssh_conn", lambda s: _PUB_SESS159)
        _p9_patch(_hosts178, "_tailscale_conn_state", lambda s: (True, False))
        _p9_patch(_ue178, "ts_netfilter_on", lambda s: False)
        _p9_patch(_ue178, "app_profiles", lambda s: None)
        _p9_patch(_fw178, "_fwa_read_stored", lambda server: None)
        r = _p9_client(P9_ADMIN).post("/api/remote/%d/ssh-port" % P9_HOST, json={"port": 2022})
        return r.status_code, _p9_json(r), box.allows, _p9_audit("change_ssh_port")
    finally:
        _p9_restore_all()


_rt178 = _route_move178([_PUB22_163])
check("1109 finding 4 (route): POST /api/remote/<id>/ssh-port on that host answers the refusal (success false, "
      "naming the IPv4 rule), sends no allow verb, and audits the move as failed",
      _rt178[0] == 200 and _rt178[1].get("success") is False and _UNREAD178 in (_rt178[1].get("message") or "")
      and _rt178[2] == [] and _rt178[3].success is False and _rt178[3].detail == "22 -> 2022",
      repr((_rt178[0], _rt178[1], _rt178[2], getattr(_rt178[3], "detail", None))))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# LinuxGSM v26.6.0 dropped btl and onset
# ════════════════════════════════════════════════════════════════════════════════════════════════
_named178 = []
for _d178, _dirs178, _files178 in os.walk(os.path.join(_root, "panel")):
    _dirs178[:] = [d for d in _dirs178 if d not in ("vendor", "__pycache__")]
    for _f178 in _files178:
        if _f178.endswith((".py", ".js", ".html", ".json")):
            with open(os.path.join(_d178, _f178), encoding="utf-8") as _fh178:
                if _re178.search(r"\b(btl|onset|btlserver|onsetserver)\b", _fh178.read()):
                    _named178.append(os.path.relpath(os.path.join(_d178, _f178), _root))
check("1109 LinuxGSM v26.6.0: the panel's cap table is empty (LinuxGSM's check_deps.sh refuses no game since it "
      "dropped btl and onset), Onset is no player-download HTTP game, and no panel source names either game",
      _lgsm178._LGC_DISTRO_CAPS == {} and _lgsm178.lgc_distro_caps("btl") == ""
      and "onset" not in _game178._LGC_PLAYER_HTTP_GAMES and _named178 == [],
      repr((_lgsm178._LGC_DISTRO_CAPS, sorted(_game178._LGC_PLAYER_HTTP_GAMES), _named178)))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# The complexity gate stops when git's diff fails
# ════════════════════════════════════════════════════════════════════════════════════════════════
_cxd178 = _tf178.mkdtemp(prefix="lgsm-unit-p178-")      # part28's own directory is gone by now
_sp178.run(["git", "init", "-q", "-b", "main", _cxd178], env=_GIT28, capture_output=True, check=True)  # nosec
_cx28._test_commit(_cxd178, _GIT28, {"m.py": "X = 1\n"}, "base")
_cxbase178 = _sp178.run(["git", "rev-parse", "HEAD"], cwd=_cxd178, env=_GIT28, capture_output=True,  # nosec
                        text=True, check=True).stdout.strip()
_cx28._test_commit(_cxd178, _GIT28, {"m.py": "X = 2\n", "n.py": "Y = 1\n"}, "head")


def _gate178(fn, *a):
    try:
        return fn(*a, cwd=_cxd178)
    except RuntimeError as e:
        return "RuntimeError: " + str(e)[:80]


_missing178 = "0123456789abcdef0123456789abcdef01234567"
_bad178 = {"changed_files": _gate178(_cx28.changed_files, _missing178),
           "_renamed_from": _gate178(_cx28._renamed_from, _missing178),
           "run": _gate178(_cx28.run, _missing178)}
check("1109 complexity gate: a base the checkout lacks stops the gate (git's diff failed) in the changed-file "
      "list, the rename list and the run: read without git's exit status, it listed no file and the gate "
      "passed having judged nothing",
      all(isinstance(v, str) and v.startswith("RuntimeError: git diff") for v in _bad178.values()), repr(_bad178))
check("1109 complexity gate: ...while a base it has lists the change's files (control)",
      sorted(_gate178(_cx28.changed_files, _cxbase178)) == ["m.py", "n.py"],
      repr(_gate178(_cx28.changed_files, _cxbase178)))
_sh178.rmtree(_cxd178, ignore_errors=True)

check("part178: nothing reached a host, sudo, ufw, a resolver or data/ (the transport tripwire)",
      _P9_TRIPPED[_TRIP178_START:] == [], repr(_P9_TRIPPED[_TRIP178_START:][:4]))
