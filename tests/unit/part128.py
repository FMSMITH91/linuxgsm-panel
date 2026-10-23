"""Part 128 of the unit suite: review 1022c, builder A (system ops, install, the debug report).

* A panel unit that is only "enabled-runtime" (a link under /run, gone at the next boot) counted as
  starting at boot: a clean reboot of the panel's own host left out "the panel will not come back"
  and told players its panel-started servers would be back; Diagnostics' Service check said nothing.
* The startup banner named the FIRST tailnet address for a panel bound to another one (its IPv6
  address), which a socket on that address never answers; for the IPv4-only wildcard it now names an
  IPv4 address.
* NodeSource's key was dearmored by root to "<mktemp file>.gpg" in /tmp, a name another account
  could plant first as a link that gpg writes through; both forms (install.sh and the remote
  bootstrap) now write it inside their private mktemp -d directory.
* The debug report's "Ways in" read sshd's ports from `sshd -T` only; under socket activation that is
  sshd_config's Port, which systemd ignores, so a moved SSH port read as "SSH: no rule".
* Cancel during the arming of a clean reboot said "the reboot has been sent" before it was.
* A check-runs answer that is not GitHub's shape raised out of the update gate instead of "unknown".

HOW IT RUNS. In-process on stand-ins (part12's patcher and transport tripwire); the two NodeSource
forms under bash over this part's own temp dir, with mktemp, curl, dpkg, apt-get and gpg's key
listing as shell functions (gpg itself only dearmors). Nothing reaches a host, sudo or data/.
"""
import os
import pathlib as _pl128
import shlex as _shlex128
import shutil as _shutil128
import subprocess as _sp128  # nosec B404 - bash and gpg over this part's own temp files, fixed argv
import tempfile as _tf128
import time as _time128
from types import SimpleNamespace as _NS128

from unit.part01 import _r21d_urlopen_of, check, skip
from unit.part05 import _ns_apt_ni, _ns_code_lines, _ns_fn
from unit.part12 import _P9_TRIPPED, _p9_arm, _p9_patch, _p9_restore_all
from unit.part114 import _TS_ADDR114
from unit.part32 import _ALL_IFACES
from panel.core import config as _cfg128
from panel.ops import serve_upkeep as _su128
from panel.ops import system_ops as _so128
from panel.ops.debug_report import _src_systemd as _sysd128
from panel.ops.debug_report import network as _nw128
from panel.security import privileged as _priv128
from panel.services import host_reboot as _hr128

_TRIP128_START = len(_P9_TRIPPED)
_TMP128 = _tf128.mkdtemp(prefix="lgsm-unit-p128-")
_TS6_128 = "fd7a:115c:a1e0::128"  # NOSONAR(S1313) - a tailnet (ULA) IPv6 address in a stand-in node


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. "enabled-runtime" does not start at boot
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _boot128():
    got = {}
    for state in ("enabled", "enabled-runtime", "disabled"):
        props = {"UnitFileState": state, "MainPID": str(os.getpid())}
        _p9_patch(_sysd128, "unit_show", lambda timeout=5, _p=props: {
            "scope": "system", "props": dict(_p), "error": None})
        got[state] = (_so128.panel_starts_at_boot(), _so128._service_problems("system", props))
        _p9_restore_all()
    check("panel unit: only 'enabled' starts at boot; 'enabled-runtime' (a /run link, gone at the reboot "
          "asked about) is neither counted as coming back nor passed by the Service check",
          got == {"enabled": (True, []),
                  "enabled-runtime": (False, ["the unit is enabled-runtime, so it does not start at boot"]),
                  "disabled": (False, ["the unit is disabled, so it does not start at boot"])}, repr(got))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The startup banner's tailnet address
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _banner128():
    info = _NS128(tailscale_ips=[_TS_ADDR114, _TS6_128], serve_config={})
    info6 = _NS128(tailscale_ips=[_TS6_128, _TS_ADDR114], serve_config={})

    def _line(bind, inf):
        lines = _su128._tailscale_banner({}, 5000, {"BOOT_BIND": bind}, inf, lambda st, conf: "http")
        return lines[0].strip() if lines else None
    got = {
        "bound to the IPv6 address": _line(_TS6_128, info),
        "bound to the IPv4 address": _line(_TS_ADDR114, info6),
        "IPv4 wildcard, IPv6 listed first": _line(_ALL_IFACES, info6),
        "control: every address": _line("::", info),
    }
    want = {
        "bound to the IPv6 address": "🌐 Tailscale IP: http://[%s]:5000" % _TS6_128,
        "bound to the IPv4 address": "🌐 Tailscale IP: http://%s:5000" % _TS_ADDR114,
        "IPv4 wildcard, IPv6 listed first": "🌐 Tailscale IP: http://%s:5000" % _TS_ADDR114,
        "control: every address": "🌐 Tailscale IP: http://%s:5000" % _TS_ADDR114,
    }
    check("startup banner: a panel bound to one tailnet address is named at THAT address (it printed the "
          "first listed, which the socket never answers), and the IPv4 wildcard at an IPv4 one",
          got == want, repr(got))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. NodeSource's dearmored key never goes to a predictable name in /tmp
# ════════════════════════════════════════════════════════════════════════════════════════════════
_FPR128 = "AB" * 20


def _ns_shims128(d, armored):
    """Shell stand-ins: mktemp (its file at a fixed, pre-planted name), curl, dpkg, apt-get, gpg's listing."""
    q = _shlex128.quote
    return "\n".join([
        'mktemp() { if [ "$1" = -d ]; then command mktemp -d -p %s; else : > %s; echo %s; fi; }'
        % (q(d), q(os.path.join(d, "k")), q(os.path.join(d, "k"))),
        'curl() { cp %s "${@: -1}"; }' % q(armored),
        "dpkg() { echo amd64; }",
        "apt-get() { :; }",
        "gpg() { case \" $* \" in *\" --show-keys \"*) printf 'pub:u:255:22:X:1::::::::\\nfpr:::::::::%s:\\n' ;; "
        "*) command gpg \"$@\" ;; esac; }" % _FPR128,
    ])


def _ns_case128(form, armored):
    """(victim's bytes afterwards, the keyring written, rc) with "<mktemp file>.gpg" planted as a link."""
    d = os.path.join(_TMP128, "ns-" + form)
    _shutil128.rmtree(d, ignore_errors=True)
    os.makedirs(os.path.join(d, "out"))
    victim = os.path.join(d, "victim")
    with open(victim, "w") as f:
        f.write("VICTIM\n")
    os.symlink(victim, os.path.join(d, "k.gpg"))
    keyring = os.path.join(d, "out", "keyrings", "nodesource.gpg")
    dests = {"KEYRING": keyring, "SOURCES": os.path.join(d, "out", "nodesource.sources"),
             "PREFS": os.path.join(d, "out", "nodejs")}
    q = _shlex128.quote
    if form == "install.sh":
        body = "\n".join([
            "\n".join(ln for ln in _ns_code_lines if ln.startswith("NODESOURCE_")),
            _ns_fn("nodesource_key_ok"), _ns_fn("nodesource_setup"), _ns_apt_ni,
            "NODESOURCE_KEY_FPR=%s" % q(_FPR128),
            "\n".join("NODESOURCE_%s=%s" % (k, q(v)) for k, v in dests.items()),
            "_r30a_apt_ni() { :; }",
            "nodesource_setup ''",
        ])
    else:
        saved = {n: getattr(_priv128, n) for n in ("NODESOURCE_FINGERPRINT", "NODESOURCE_KEYRING",
                                                    "NODESOURCE_SOURCES", "NODESOURCE_PREFS")}
        try:
            _priv128.NODESOURCE_FINGERPRINT = _FPR128
            for k, v in dests.items():
                setattr(_priv128, "NODESOURCE_" + k, v)
            body = _priv128.remote_command("nodesource-setup", [])
        finally:
            for n, v in saved.items():
                setattr(_priv128, n, v)
    p = _sp128.run(["bash", "-c", _ns_shims128(d, armored) + "\n" + body],  # nosec B603 B607
                   capture_output=True, text=True, timeout=60, check=False)
    with open(victim) as f:
        after = f.read()
    try:
        with open(keyring, "rb") as f:
            written = f.read()
    except OSError:
        written = None
    return after, written, p.returncode, (p.stdout + p.stderr)[-300:]


def _nodesource128():
    if not _shutil128.which("gpg"):
        skip("nodesource (install.sh and remote): the dearmored key is written inside the private "
             "directory, never through a link planted beside the mktemp file", "no gpg on this machine")
        return
    home = os.path.join(_TMP128, "gnupg")
    os.mkdir(home, 0o700)
    armored = os.path.join(_TMP128, "armored.asc")
    p = _sp128.run(["gpg", "--batch", "--homedir", home, "--enarmor"],  # nosec B603 B607
                   input=b"KEYRING-BYTES\n", capture_output=True, timeout=60, check=False)
    with open(armored, "wb") as f:
        f.write(p.stdout)
    got = {form: _ns_case128(form, armored) for form in ("install.sh", "remote")}
    check("nodesource (install.sh and remote): the dearmored key is written inside the private mktemp -d "
          "directory, so a link planted at '<mktemp file>.gpg' is never written through, and the keyring "
          "still gets the key",
          all(v[:3] == ("VICTIM\n", b"KEYRING-BYTES\n", 0) for v in got.values()), repr(got))


def _r36j_ns_leak128():
    """The remote NodeSource script when `mktemp -d` fails: the key file `mktemp` made is still removed."""
    q = _shlex128.quote
    got = {}
    for case, dir_ok in (("mktemp -d fails", False), ("control: both made", True)):
        d = os.path.join(_TMP128, "ns-leak-" + str(dir_ok))
        _shutil128.rmtree(d, ignore_errors=True)
        os.makedirs(d)
        k = os.path.join(d, "k")
        shims = "\n".join([
            'mktemp() { if [ "$1" = -d ]; then %s; else : > %s; echo %s; fi; }'
            % ("command mktemp -d -p " + q(d) if dir_ok else "return 1", q(k), q(k)),
            "curl() { return 1; }", "dpkg() { echo amd64; }", "apt-get() { :; }", "gpg() { :; }"])
        script = shims + "\n" + _priv128.remote_command("nodesource-setup", [])
        p = _sp128.run(["bash", "-c", script],  # nosec B603 B607
                       capture_output=True, text=True, timeout=60, check=False)
        got[case] = (p.returncode, os.path.exists(k), sorted(os.listdir(d)))
    check("nodesource (remote): when `mktemp -d` fails after the key file was made, the script still removes "
          "the key file (its EXIT trap was set after both mktemps); with both made, both are removed (control)",
          got == {"mktemp -d fails": (1, False, []), "control: both made": (1, False, [])}, repr(got))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. The debug report's SSH ports under socket activation
# ════════════════════════════════════════════════════════════════════════════════════════════════
_UFWHEAD128 = ("Status: active\n\nTo                         Action      From\n"
               "--                         ------      ----\n")


def _sshd_report128():
    sock_on = ("ActiveState=active\nListen=0.0.0.0:2222 (Stream)\nListen=[::]:2222 (Stream)\n", "", 0)
    sock_off = ("ActiveState=inactive\n", "", 0)
    got = {}
    for name, sock in (("socket-activated", sock_on), ("socket inactive", sock_off),
                       ("systemd unread", ("", "could not start", -1))):
        asked = []
        _p9_patch(_so128, "_debug_run", lambda argv, timeout=5, cap=None, _s=sock: (asked.append(argv), _s)[1])
        _p9_patch(_nw128, "priv_read", lambda verb, args, timeout: ("port 22\n", "", 0)
                  if verb == "sshd-effective-config" else None)
        ports = _nw128.sshd_ports_read()
        u = _nw128.ufw_classify(_UFWHEAD128 + "2222/tcp                   ALLOW IN    Anywhere\n", "", 0)
        got[name] = (ports, _nw128._ways_in(u, 5000, {}, ports).split(" · ")[0],
                     all(a[:2] == ["systemctl", "show"] for a in asked))
        _p9_restore_all()
    check("debug report: on a socket-activated host Ways in checks ssh.socket's ports (sshd -T's Port, which "
          "systemd ignores, read a moved SSH port as 'no rule'); with the socket inactive or unread, sshd -T's",
          got == {"socket-activated": ([2222], "SSH ALLOW from Anywhere (on sshd's own ports)", True),
                  "socket inactive": ([22], "SSH: no rule (on sshd's own ports)", True),
                  "systemd unread": ([22], "SSH: no rule (on sshd's own ports)", True)}, repr(got))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. Cancel while the reboot is arming
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _cancel128():
    rid = 912801
    remote = _NS128(id=rid, name="p128", display_name="p128")
    _hr128._host_reboots[rid] = {"sent": _time128.time(), "phase": "arming", "cancel": None}
    try:
        status, body = _hr128.cancel(remote, None)
    finally:
        _hr128._host_reboots.pop(rid, None)
    check("clean reboot: a Cancel refused while it arms says the reboot is under way, not that it 'has been "
          "sent' (it is not yet, and may still be rolled back), and keeps its machine-readable 'sent'",
          (status, body.get("error"), str(body.get("message")))
          == (409, "sent", "Too late to cancel: the reboot is already under way."), repr((status, body)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. A check-runs answer that is not GitHub's shape
# ════════════════════════════════════════════════════════════════════════════════════════════════
class _Resp128:
    headers = {}
    status = 200

    def __init__(self, body):
        self._b = body.encode()

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _ci_shape128():
    bodies = {
        "a JSON list": "[]",
        "a run that is not an object": '{"check_runs": [1]}',
        "a name that is not text": '{"check_runs": [{"name": [], "status": "completed", "conclusion": null}]}',
        "a state that is not text": '{"check_runs": [{"name": "x", "status": {}, "conclusion": null}]}',
        "control: GitHub's shape": '{"check_runs": [{"name": "x", "status": "completed", "conclusion": "success"}]}',
    }
    got = {}
    for name, body in bodies.items():
        _p9_patch(_r21d_urlopen_of(_so128), "urlopen", lambda req, timeout=8, _b=body: _Resp128(_b))
        try:
            got[name] = _so128._ci_fetch_runs("o/r", "a" * 40, {})
        except Exception as exc:  # noqa: BLE001 - what escaped is the finding
            got[name] = type(exc).__name__
        finally:
            _p9_restore_all()
    want = dict({n: "unknown" for n in bodies}, **{
        "control: GitHub's shape": [{"name": "x", "status": "completed", "conclusion": "success"}]})
    check("update gate: a check-runs answer that is not GitHub's shape reads as 'unknown' (it raised "
          "AttributeError/TypeError out of the gate), and GitHub's own shape is read as before",
          got == want, repr(got))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# The config cache: a replaced file of the same size in the same timestamp tick (integration)
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _cfg_cache128():
    d = _pl128.Path(_TMP128) / "cfg"
    d.mkdir()
    path, saved = d / "config.json", dict(_cfg128._cfg_cache)
    _p9_patch(_cfg128, "CONFIG_FILE", path)
    got = {}
    try:
        _cfg128._cfg_cache.update(key=None, data={})
        path.write_text('{"site_title": "AAAA"}', encoding="utf-8")
        st = path.stat()
        got["first read"] = _cfg128.load_config().get("site_title")
        # An atomic writer's shape (save_config, install.sh): a new file renamed over the old one. Same size,
        # and the old file's times, as two writes inside one coarse timestamp tick leave them.
        new = d / "config.json.new"
        new.write_text('{"site_title": "BBBB"}', encoding="utf-8")
        os.utime(new, ns=(st.st_atime_ns, st.st_mtime_ns))
        os.replace(new, path)
        got["replaced: same size, same times"] = _cfg128.load_config().get("site_title")
        _cfg128.save_config(dict(_cfg128.load_config(), site_title="CCCC"))
        got["save_config drops the cache"] = _cfg128._cfg_cache["key"] is None
        got["after save_config"] = _cfg128.load_config().get("site_title")
    finally:
        _p9_restore_all()
        _cfg128._cfg_cache.clear()
        _cfg128._cfg_cache.update(saved)
    check("config: load_config's cache is keyed on the file's inode too, so a config.json replaced by one of "
          "the same size inside one timestamp tick is read again (it served the stale config), and "
          "save_config drops the cache",
          got == {"first read": "AAAA", "replaced: same size, same times": "BBBB",
                  "save_config drops the cache": True, "after save_config": "CCCC"}, repr(got))


try:
    _p9_arm(who="part128")
    for _fn128 in (_boot128, _banner128, _nodesource128, _r36j_ns_leak128, _sshd_report128, _cancel128, _ci_shape128,
                   _cfg_cache128):
        _fn128()
        _p9_restore_all()
        _p9_arm(who="part128")
finally:
    _p9_restore_all()
    _shutil128.rmtree(_TMP128, ignore_errors=True)

check("part128: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP128_START, repr(_P9_TRIPPED[_TRIP128_START:][:6]))
