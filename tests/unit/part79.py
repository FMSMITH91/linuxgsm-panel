"""Part 79 of the unit suite: the tenth review's core, ssh-core, system and locale fixes (builder A).

Held here, each against the code path the finding named:

* A Tailscale remote stored by its IPv6 tailnet address is dialled as that address: the MagicDNS
  suffix was glued onto it (`fd7a:…::1.tail1234.ts.net`), on both transports.
* A Tailscale join validates its route list BEFORE switching IP forwarding on: `a, b` (a space)
  left the host forwarding with nothing joined, and the key flow blamed the auth key.
* A host that cannot be reached answers 200, not 502 (Cloudflare swaps a 502 for its own page);
  a changed host key and a command cut off part-way are said as that, not as "unreachable", and
  the cause is logged.
* system_ops._run_verb on a panel host without the helper: a helper-only verb is refused on the
  shell branch too (it ran a bare `sudo`), and both no-helper paths run in the C locale.
* sudo's OWN refusal is read in C: every `sudo bash -c` wrap and every `sudo -n` argv starts sudo
  in C.UTF-8 with an empty LANGUAGE, so a German host's refusal reads as "refused".
* install.sh reads `ufw status` in C: a German host's active UFW read as inactive at install.
* A number awk formats (RAM percent, the specs card's RAM) and df's sizes are read in C: mawk,
  Ubuntu's default awk, printed a German decimal comma.

HOW IT RUNS. Stubs through part12's _p9_patch, undone in the finally; nothing reaches a transport.
The locale checks run bash on stand-in `sudo` and `ufw` programs in this part's own temp dir that
answer in German unless started the way the fix starts them (classic sudo keeps an exported
LANGUAGE, and fills an unset one in from /etc/default/locale through PAM).
"""
import json as _json79
import logging as _logging79
import os
import shutil as _shutil79
import subprocess as _sp79  # nosec B404 - runs bash on this repo's own text and stand-ins
import tempfile as _tf79
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part05 import _root
from unit.part12 import _p9, _p9_patch, _p9_restore_all
from panel.core import http as _http79
from panel.ops import system_ops as _so79, tailscale_integration as _ts79
from panel.ops.ssh_manager import _core as _core79, hosts as _hosts79
from panel.security import privileged as _priv79

_TMP79 = os.path.realpath(_tf79.mkdtemp(prefix="lgsm-unit-p79-"))


def _read79(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _cat79(lang):
    with open(os.path.join(_root, "translations", lang, "r20a.json"), encoding="utf-8") as fh:
        return _json79.load(fh)


def _stand_in79(name, body):
    path = os.path.join(_TMP79, "bin", name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("#!/bin/bash\n" + body)
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stand-in program this part runs
    os.chmod(path, 0o700)
    return path


# A German host: sudo and ufw speak German unless started with LC_ALL=C.UTF-8 (or C) and no
# LANGUAGE. The stand-in sudo does what classic sudo does with the environment: a LANGUAGE the
# caller exported (even empty) is kept; an unset one is filled in by PAM from /etc/default/locale.
_C_TEST79 = ('_c() { [ "$LC_ALL" = C ] || { [ "$LC_ALL" = C.UTF-8 ] && [ -z "$LANGUAGE" ]; }; }\n')
# Its policy refuses `bash` and `true` (a host that wants a password for them) and runs anything else.
_stand_in79("sudo", _C_TEST79 + (
    '[ "$1" = -n ] && shift\n'
    'if [ "$1" = bash ] || [ "$1" = true ]; then\n'
    '    if _c; then echo "sudo: a password is required" >&2; else echo "sudo: Ein Passwort ist notwendig" >&2; fi\n'
    '    exit 1\n'
    'fi\n'
    '[ "${LANGUAGE+set}" = set ] || export LANGUAGE=de\n'
    'exec "$@"\n'))
_stand_in79("ufw", _C_TEST79 + (
    'if _c; then echo "Status: active"; echo; echo "To  Action  From"; '
    'else echo "Status: aktiv"; echo; echo "Zu  Aktion  Von"; fi\n'
    'echo "--  ------  ----"\necho "5000/tcp  ALLOW  Anywhere"\n'))
_GERMAN79 = {"PATH": os.path.join(_TMP79, "bin") + ":/usr/bin:/bin", "HOME": _TMP79,
             "LANG": "de_DE.UTF-8", "LANGUAGE": "de"}


def _try79(fn, *a, **k):
    """Return fn's answer, or ("raised", <class>): a raise is a failed check by name, not a dead part."""
    try:
        return fn(*a, **k)
    except Exception as exc:  # noqa: BLE001 - reported by class, in the check that reads it
        return ("raised", type(exc).__name__)


def _bash79(script, env=None):
    r = _sp79.run(["/bin/bash", "-c", script],  # nosec B603 - bash on this part's own text
                  capture_output=True, text=True, timeout=60, env=env or _GERMAN79)
    return r.stdout.strip(), r.stderr.strip(), r.returncode


try:
    # ════════════════════════════════════════════════════════════════════════════════════════════
    # 1. Tailscale: an IPv6 tailnet address is not a bare node name
    # ════════════════════════════════════════════════════════════════════════════════════════════
    _p9_patch(_ts79, "get_tailscale_info", lambda *a, **k: NS(dns_name="panel.tail1234.ts.net."))
    _hosts_in79 = ("fd7a:115c:a1e0::1234", "[fd7a:115c:a1e0::1234]", "fe80::1%eth0", "100.101.1.2",
                   "vps-one", "vps-one.tail1234.ts.net")
    _want79 = ["fd7a:115c:a1e0::1234", "[fd7a:115c:a1e0::1234]", "fe80::1%eth0", "100.101.1.2",
               "vps-one.tail1234.ts.net.", "vps-one.tail1234.ts.net"]
    _cli79 = [_core79._resolve_ts_host(NS(host=h)) for h in _hosts_in79]
    _pmk79 = [_core79._tailscale_connect_host(NS(host=h)) for h in _hosts_in79]
    check("tailscale host: an IPv6 tailnet address is dialled as itself on the ssh-CLI path (it got "
          "the MagicDNS suffix glued on), and a bare node name still gets it",
          _cli79 == _want79, repr(_cli79))
    check("tailscale host: ...and the same on the paramiko path (one helper for both twins)",
          _pmk79 == _want79, repr(_pmk79))

    # ════════════════════════════════════════════════════════════════════════════════════════════
    # 2. Tailscale join: the route list is checked before IP forwarding is switched on
    # ════════════════════════════════════════════════════════════════════════════════════════════
    _seen79 = []

    def _wrf79(server, target, content, timeout=15):
        _seen79.append(("write", target))
        return "", "", 0

    def _rp79(server, verb, args=(), timeout=30, **k):
        _priv79.check_args(verb, list(args))     # the boundary's own validation, as the helper does
        _seen79.append((verb, tuple(args)))
        return "", "", 0

    _p9_patch(_core79, "write_root_file", _wrf79)
    _p9_patch(_core79, "run_privileged", _rp79)
    _p9_patch(_hosts79, "remote_check_tailscale",
              lambda s: {"running": True, "tailscale_ip": "100.101.1.2", "dns_name": "vps"})
    _key79 = "tskey-auth-" + "k1234567890abcdef"
    _bad79 = _try79(_hosts79.remote_bootstrap_tailscale, NS(name="h"), auth_key=_key79,
                    advertise_routes="192.168.1.0/24,nope")
    _bad_seen79, _seen79[:] = list(_seen79), []
    _badl79 = _try79(_hosts79.remote_tailscale_up_url, NS(name="h"), advertise_routes="10.0.0.0/8;id")
    _badl_seen79, _seen79[:] = list(_seen79), []
    check("tailscale join (key): a route list that is not one is refused BEFORE IP forwarding is "
          "written, saying it is the routes (it blamed the auth key and left forwarding on)",
          _bad79[0] is False and _bad79[1] == _hosts79._R20A_BAD_ROUTES and _bad_seen79 == [],
          repr((_bad79[:2], _bad_seen79)))
    check("tailscale join (login link): ...and the same on the link flow",
          _badl79 == (False, _hosts79._R20A_BAD_ROUTES) and _badl_seen79 == [],
          repr((_badl79, _badl_seen79)))
    _ok79 = _try79(_hosts79.remote_bootstrap_tailscale, NS(name="h"), auth_key=_key79,
                   advertise_routes=" 192.168.1.0/24, 10.0.0.0/24 ")
    _ok_seen79, _seen79[:] = list(_seen79), []
    _none79 = _try79(_hosts79.remote_bootstrap_tailscale, NS(name="h"), auth_key=_key79,
                     advertise_routes="-")
    _none_seen79, _seen79[:] = list(_seen79), []
    check("tailscale join: a list typed with spaces after the commas joins (the verb gets it "
          "canonical), and \"-\" or nothing writes no forwarding",
          _ok79[0] is True and ("write", "sysctl-tailscale") in _ok_seen79
          and any(v == "tailscale-up-key" and a[2] == "192.168.1.0/24,10.0.0.0/24" for v, a in _ok_seen79)
          and _none79[0] is True and not any(v == "write" for v, _a in _none_seen79),
          repr((_ok79[:2], _ok_seen79, _none_seen79)))

    # ════════════════════════════════════════════════════════════════════════════════════════════
    # 3. A host that cannot be reached: 200, and a changed key / a cut-off command said as that
    # ════════════════════════════════════════════════════════════════════════════════════════════
    _logged79 = []

    class _Grab79(_logging79.Handler):
        def emit(self, record):
            _logged79.append(record.getMessage())

    _grab79 = _Grab79()
    _p9.logger.addHandler(_grab79)
    _was_disabled79 = _p9.logger.disabled
    _p9.logger.disabled = False
    try:
        class HostKeyMismatch(ConnectionError):     # matched by class NAME, as monitoring reads it
            pass

        _cut79 = ConnectionError("Command failed: socket closed")
        _cut79.command_started = True
        with _p9.test_request_context("/api/remote/1/firewall/open"):
            _down79 = _http79.unreachable_error("firewall_open", ConnectionError("timed out"))
            _key_r79 = _http79.unreachable_error("firewall_open", HostKeyMismatch("key CHANGED for h"))
            _cut_r79 = _http79.unreachable_error("firewall_open", _cut79)
            try:
                raise HostKeyMismatch("key CHANGED for h")
            except ConnectionError:
                _route79 = _http79._unreachable("ubuntu pro")      # a route's own catch
        _ans79 = {k: (r[1], r[0].get_json()) for k, r in
                  (("down", _down79), ("key", _key_r79), ("cut", _cut_r79), ("route", _route79))}
    finally:
        _p9.logger.removeHandler(_grab79)
        _p9.logger.disabled = _was_disabled79
    check("unreachable: the app handler's answer is a 200 (a 502 is swapped for Cloudflare's own "
          "page, so the JSON never reached the page), still saying the host is unreachable",
          _ans79["down"][0] == 200 and _ans79["down"][1].get("unreachable") is True
          and _ans79["down"][1].get("message") == "Host unreachable", repr(_ans79["down"]))
    check("unreachable: a changed host key is said as that and points at Re-trust host key, on the "
          "app handler and on a route's own catch; a command cut off part-way says it may have run",
          _ans79["key"][1].get("message") == _http79._R20A_HOSTKEY
          and _ans79["key"][1].get("unreachable") is False
          and _ans79["route"][1].get("message") == _http79._R20A_HOSTKEY
          and _ans79["cut"][1].get("message") == _http79._R20A_STARTED
          and _ans79["cut"][1].get("unreachable") is False, repr(_ans79))
    check("unreachable: the cause is logged (class and text), where only 'host unreachable' was",
          any("HostKeyMismatch" in m and "key CHANGED" in m for m in _logged79)
          and any("timed out" in m for m in _logged79), repr(_logged79))
    _es79, _fr79 = _cat79("es"), _cat79("fr")
    _new79 = (_http79._R20A_HOSTKEY, _http79._R20A_STARTED, _hosts79._R20A_BAD_ROUTES)
    check("unreachable / tailscale join: every new sentence has an es and a fr translation",
          all(_es79.get(s) and _fr79.get(s) for s in _new79), repr([s for s in _new79 if s not in _es79]))

    # ════════════════════════════════════════════════════════════════════════════════════════════
    # 4. system_ops._run_verb with no helper: the helper-only refusal, and the C locale
    # ════════════════════════════════════════════════════════════════════════════════════════════
    _pop79 = []

    class _Sub79:
        PIPE, DEVNULL, TimeoutExpired = _sp79.PIPE, _sp79.DEVNULL, _sp79.TimeoutExpired

        @staticmethod
        def Popen(argv, **k):
            _pop79.append((argv, k))
            return NS(pid=0)

        @staticmethod
        def run(argv, **k):
            _pop79.append((argv, k))
            return NS(returncode=1, stdout="", stderr="")

    class _euid79:
        """os, with geteuid answering `uid`."""

        def __init__(self, uid):
            self._uid = uid

        def geteuid(self):
            return self._uid

        def __getattr__(self, name):
            return getattr(os, name)

    _p9_patch(_so79, "subprocess", _Sub79)
    _p9_patch(_so79, "_collect_verb_output", lambda p, argv, timeout, *a, **k: ("ok", "", 0))
    _p9_patch(_so79, "_helper_present", lambda: False)
    _p9_patch(_so79, "os", _euid79(1000))
    _ti79 = _try79(_so79._run_verb, "tailscale-install", [], timeout=5)
    _ti_pop79, _pop79[:] = list(_pop79), []
    # The other two ways a non-root panel host starts sudo itself: the helper probe's
    # `sudo -n <helper> --list-verbs` and the debug report's `sudo -n <tool>` (system_ops._run's
    # `sudo <cmd>` is part10's "so/_run" check).
    _try79(_so79._helper_probe_run)
    from panel.ops.debug_report import network as _net79
    _p9_patch(_net79, "subprocess", _Sub79)
    _try79(_net79.sudo_n_verb, "ufw-status", ["numbered"], 5)
    _three_pop79, _pop79[:] = list(_pop79), []
    _so79._run_verb("ufw-status", ["numbered"], timeout=5)
    _sh_pop79, _pop79[:] = list(_pop79), []
    _p9_patch(_so79, "os", _euid79(0))
    _so79._run_verb("ufw-status", ["numbered"], timeout=5)
    _rt_pop79, _pop79[:] = list(_pop79), []
    _p9_patch(_so79, "_helper_present", lambda: True)
    _so79._run_verb("ufw-status", ["numbered"], timeout=5)
    _he_pop79, _pop79[:] = list(_pop79), []
    check("system_ops: a helper-only verb on a non-root panel host with no helper says it needs the "
          "helper, and starts nothing (it ran a bare `sudo` and showed sudo's usage text)",
          len(_ti79) == 3 and _ti79[2] == -1 and "privileged helper" in _ti79[1] and _ti_pop79 == [],
          repr((_ti79, _ti_pop79)))

    def _env_ok79(pops):
        """Whether the child's environment is C.UTF-8 with LANGUAGE set EMPTY.

        Empty: sudo keeps it, where PAM would fill an unset one in from /etc/default/locale.
        """
        env = pops[0][1].get("env") if pops else None
        return bool(env) and env.get("LC_ALL") == "C.UTF-8" and env.get("LANGUAGE") == ""

    _shell79 = _sh_pop79[0][0] if _sh_pop79 else ""
    check("system_ops: the no-helper shell path (`sudo <verb>`) runs in C, sudo itself included",
          _env_ok79(_sh_pop79) and _shell79 == "sudo " + _priv79.remote_command("ufw-status", ["numbered"]),
          repr(_sh_pop79))
    check("system_ops: ...and the root path and the helper path hand their argv a C environment",
          _env_ok79(_rt_pop79) and _env_ok79(_he_pop79)
          and _rt_pop79[0][0] == ["ufw", "status", "numbered"], repr((_rt_pop79, _he_pop79)))
    check("sudo refusal: the helper probe and the debug report's `sudo -n` start sudo in C (each "
          "classes a refusal by sudo's English words)",
          len(_three_pop79) == 2 and all(a[:2] == ["sudo", "-n"] for a, _k in _three_pop79)
          and _env_ok79(_three_pop79[:1]) and _env_ok79(_three_pop79[1:]), repr(_three_pop79))
    check("system_ops: its sudo prefix is _core's (they cannot drift apart)",
          _so79._R20A_SUDO_C == _core79._R20A_SUDO_C, repr(_so79._R20A_SUDO_C))

    # ════════════════════════════════════════════════════════════════════════════════════════════
    # 5. sudo's own refusal, read in C
    # ════════════════════════════════════════════════════════════════════════════════════════════
    _argv79 = []
    _p9_patch(_core79, "helper_present", lambda: True)
    _p9_patch(_core79, "_real_subprocess",
              NS(Popen=lambda argv, **k: (_argv79.append((argv, k.get("env"))), NS(pid=0))[1]))
    _p9_patch(_core79, "_finish", lambda p, timeout, stdin_text=None: ("", "", 0))
    _core79._run_privileged(NS(is_local=True, auth_method="local", host="localhost"), "ufw-status",
                            ["numbered"], 10, True, None)
    check("ssh_manager: the local helper call (`sudo -n <helper>`) runs in C",
          _argv79 and _argv79[0][0][:2] == ["sudo", "-n"] and (_argv79[0][1] or {}).get("LC_ALL") == "C.UTF-8"
          and (_argv79[0][1] or {}).get("LANGUAGE") == "", repr(_argv79[:1]))
    # The wrap itself, through a real bash on the German stand-in sudo: what a refused sudo says
    # is classed "refused" only when the wrap starts sudo in C.
    _wrap79 = _core79._R20A_SUDO_C + "sudo bash -c " + _core79._quote("true")
    _o79, _e79, _rc79 = _bash79(_wrap79)
    _bare79 = _bash79("sudo bash -c " + _core79._quote("true"))
    check("sudo refusal: a German host's refused `sudo bash -c` reads as refused (it was the German "
          "sentence, which no matcher knows, so it read as unreadable)",
          _core79.privileged_outcome("shell", _o79, _e79, _rc79) == "refused"
          and _core79.privileged_outcome("shell", *_bare79) == "failed",
          repr(((_o79, _e79, _rc79), _bare79)))
    _sorun79 = _bash79(_so79._R20A_SUDO_C + "sudo -n true")
    check("sudo refusal: ...and system_ops' `sudo <cmd>` (the same prefix) is classed too",
          _so79._sudo_refusal_class(_sorun79[1]) == "a password is required", repr(_sorun79))

    # ════════════════════════════════════════════════════════════════════════════════════════════
    # 6. install.sh reads `ufw status` in C
    # ════════════════════════════════════════════════════════════════════════════════════════════
    _INS79 = _read79("install.sh")
    _head79 = "\n".join(ln for ln in _INS79[:_INS79.find("\n}\n")].splitlines()
                        if ln.startswith("export LC_ALL="))
    _i79 = _INS79.find("\nufw_port_state() {")
    _ups79 = _INS79[_i79:_INS79.find("\n}\n", _i79)] + "\n}\n" if _i79 >= 0 else "exit 3\n"
    _j79 = _INS79.find("UFW_ACTIVE=0; TS_UFW=0")
    _k79 = _INS79.find('grep -q "Status: active" && UFW_ACTIVE=1', _j79)
    _fresh79 = (_INS79[_j79:_INS79.find("\n", _k79)] + "\n    fi\nfi\n") if _j79 >= 0 and _k79 > 0 else "exit 3\n"
    _script79 = ("set -euo pipefail\n" + _head79 + "\n" + _ups79
                 + 'SUDO=""; [[ "$(id -u)" -ne 0 ]] && SUDO="sudo"\n' + _fresh79
                 + 'echo "$(ufw_port_state 5000) ${UFW_READ} ${UFW_ACTIVE}"\n')
    _de79 = _bash79(_script79)
    check("install.sh: on a German host an active UFW reads as active with the port open, on the "
          "update path (ufw_port_state) and the fresh install's (it read inactive, never opened the "
          "port, and printed the setup link as reachable)",
          _de79[0] == "open 1 1", repr(_de79))
    # ════════════════════════════════════════════════════════════════════════════════════════════
    # 7. A number awk prints is read in C (mawk, Ubuntu's default awk, prints a German decimal comma)
    # ════════════════════════════════════════════════════════════════════════════════════════════
    # Stand-ins that print as mawk and df do on a German host unless started in C: the real tool's
    # output with every decimal point a comma -- for awk, only a program that formats a number
    # (printf); a field it prints as read is passed through as mawk passes it.
    _stand_in79("awk", _C_TEST79 + (
        'case "$*" in *printf*) _c || { /usr/bin/awk "$@" | sed "s/\\([0-9]\\)\\.\\([0-9]\\)/\\1,\\2/g"; exit; } ;; esac\n'
        'exec /usr/bin/awk "$@"\n'))
    _stand_in79("df", _C_TEST79 + (
        'echo "Filesystem Size Used Avail Use% Mounted on"\n'
        'if _c; then echo "/dev/x 7.5G 3.1G 4.4G 42% /"; else echo "/dev/x 7,5G 3,1G 4,4G 42% /"; fi\n'))

    def _bash_rc79(server, cmd, timeout=30, sudo=None, **k):
        return _bash79(cmd)

    _p9_patch(_core79, "run_command", _bash_rc79)
    _up79 = _try79(_hosts79.remote_uptime, None, force=True)
    from panel.ops.ssh_manager import firewall as _fw79
    _spec79 = _try79(_fw79._compute_host_specs, NS(name="h"))
    _p9_patch(_so79, "_run", lambda cmd, timeout=30, sudo=False, text=True: _bash79(cmd))
    _sup79 = _try79(_so79.server_uptime)
    check("locale: the RAM percent awk prints is read with a decimal point on a German host "
          "(mawk printed 30,2), on a remote and on the panel's own host",
          isinstance(_up79, dict) and isinstance(_sup79, dict)
          and all(_x.get("memory_percent", "").replace(".", "", 1).isdigit() for _x in (_up79, _sup79)),
          repr((_up79, _sup79)))
    check("locale: ...and the specs card's RAM and disk size (they read 7,6 GB / 7,5G)",
          isinstance(_spec79, dict) and "," not in _spec79.get("ram", ",")
          and _spec79.get("disk") == "7.5G", repr(_spec79))

finally:
    _p9_restore_all()
    _shutil79.rmtree(_TMP79, ignore_errors=True)
