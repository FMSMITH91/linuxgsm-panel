"""Part 135 of the unit suite: the Network tab's firewall settings and port/range blocks (fw-more, PR A).

The owner: "i want more custom settings on firewall page". The tab now changes UFW's default policies
(incoming, outgoing, routed), turns it on and off, sets its logging level, blocks a port or a range
(deny or reject, TCP/UDP/both, IPv4/IPv6/both), opens a port to one address family, and blocks a whole
IP range on the Security tab. Every one of those can lock a host out, so held here:

* THE VERBS: every new argument validator, the helper's and the panel's, on good input and bad
  (injection, out of range, a reversed or empty range, a word outside its set); both tables build the
  same argv; the remote forms run under bash (and dash, where installed) against a stand-in ufw that
  records its argv, and ufw-stored-rules' shell form prints exactly what the helper's does, or nothing.
* THE READS: `ufw status verbose` in the C locale (defaults, routed disabled, logging off/on (level)); a
  translated one falls back to the stored files rather than guessing; the stored tuples read into the
  very rows real ufw 0.36.2 listed for 31 rule shapes (captured in a private namespace on copies);
  both transports' failure shapes (a paramiko raise, the -1 of tailscale/local) read as unknown.
* EVERY REFUSAL, each with its positive control: default incoming deny and turning UFW on without a
  way in for SSH or for the panel itself (rules that must NOT count: loopback, docker, a 127.0.0.1
  source, UDP, OUT, FWD, a DENY above the ALLOW); outgoing deny without confirmation or without DNS /
  HTTP / HTTPS out (and, on the panel host, its SSH out to each remote); off without confirmation; a
  port block on SSH's ports, the panel's or Tailscale's, or with sshd unreadable; a range reaching into
  the tailnet or the whitelist, covering the viewer's address or the panel's own source, or with that
  source unread; and any change while the firewall cannot be read.
* The routes: RBAC as the other firewall routes, audit rows with validated values only, and the
  settings row's script in node (a change asks first and is sent only on yes).

HOW IT RUNS. The firewall module over a stand-in host (_Host135) answering the privileged verbs from
its own state, on part12's patcher with its transport tripwire armed; routes on part12's app; the
helper loaded by part05; scripts in node. Nothing reaches a host, sudo, ufw or data/.
"""
import os
import re as _re135
import shutil as _shutil135
import subprocess as _sp135  # nosec B404 - bash/dash over this part's own temp files, fixed argv
import tempfile as _tf135
from types import SimpleNamespace as _NS135

from unit.part01 import check
from unit.part05 import _helper, _root
from unit.part12 import (P9_ADMIN, P9_HOST, P9_LOCAL, P9_VIEWER, _P9_TRIPPED, _p9, _p9_arm, _p9_audit,
                         _p9_client, _p9_patch, _p9_restore_all)
from unit.part47 import _cut47, _node47
from panel.core import config as _cfg135
from panel.ops.ssh_manager import _core as _core135, firewall as _fw135, hosts as _hosts135
from panel.routes import remote_security as _rs135
from panel.security import privileged as _priv135

_TRIP135_START = len(_P9_TRIPPED)
_TMP135 = _tf135.mkdtemp(prefix="lgsm-unit-p135-")
_SHELLS135 = [s for s in ("bash", "dash") if _shutil135.which(s)]


def _read135(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. The validators, in both tables
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _takes135(fn, value):
    try:
        fn(value)
        return True
    except ValueError:      # VerbError is a ValueError
        return False


_RANGE_OK135 = ("1", "22", "65535", "27015:27020", "1:65535", "27015:27016")
_RANGE_BAD135 = ("", "0", "65536", "27015:27015", "27020:27015", "27015:", ":27015", "22/tcp", "22 ",
                 "22\n", "+22", "-1", "22;id", "$(id)", "22:0", "1e3", "٢٢", "27015,27016",
                 "99999:100000", "22 && reboot")
_rng_bad135 = [(n, v) for n, f in (("helper", _helper.v_fwa_port_range), ("panel", _priv135._fwa_port_range))
               for v in _RANGE_OK135 if not _takes135(f, v)]
_rng_lax135 = [(n, v) for n, f in (("helper", _helper.v_fwa_port_range), ("panel", _priv135._fwa_port_range))
               for v in _RANGE_BAD135 if _takes135(f, v)]
check("fw verbs: a port or range is one port or lo<hi, 1-65535, digits only — in the helper and the panel",
      not _rng_bad135 and not _rng_lax135, repr((_rng_bad135, _rng_lax135)))

_GOOD135 = {
    "ufw-default": [["deny", "incoming"], ["reject", "outgoing"], ["allow", "routed"]],
    "ufw-disable": [[]],
    "ufw-logging": [[x] for x in ("off", "low", "medium", "high", "full")],
    "ufw-stored-rules": [[]],
    "ufw-block-port": [["deny", "27015", "tcp", "both", ""], ["reject", "27015:27020", "udp", "v4", "blk x"],
                       ["deny", "8080", "tcp", "v6", "x"]],
    "ufw-delete-block-port": [["deny", "27015:27020", "udp", "v4"]],
    "ufw-allow-port-family": [["v4", "27015", "any", "game"], ["v6", "27015", "udp", ""]],
}
_BAD135 = {
    "ufw-default": [["deny", "forward"], ["drop", "incoming"], ["deny; id", "incoming"], ["deny"]],
    "ufw-disable": [["now"]],
    "ufw-logging": [["on"], ["LOW"], ["low; reboot"], ["verbose"], []],
    "ufw-stored-rules": [["/etc/shadow"]],
    "ufw-block-port": [["allow", "27015", "tcp", "both", ""], ["limit", "22", "tcp", "both", ""],
                       ["deny", "27015", "both", "both", ""], ["deny", "27015", "tcp", "all", ""],
                       ["deny", "27015", "tcp", "both", "x'; rm -rf /"], ["deny", "27015", "tcp", "both", "a" * 61],
                       ["deny", "27015/tcp", "tcp", "both", ""], ["deny", "27015", "tcp", "both"]],
    "ufw-delete-block-port": [["deny", "27015", "tcp", "both", "extra"]],
    "ufw-allow-port-family": [["both", "27015", "any", ""], ["v4", "27015", "icmp", ""],
                              ["v4", "27015", "tcp", "$(id)"]],
}
_vbad135 = []
for _v135, _cases135 in _GOOD135.items():
    for _a135 in _cases135:
        try:
            _h_argv135 = _helper.VERBS[_v135][1](_helper.validate(_v135, list(_a135)))
            _p_argv135 = _priv135.tool_argv(_v135, list(_a135))
            if [str(x) for x in _h_argv135[1:]] != [str(x) for x in _p_argv135[1:]]:
                _vbad135.append(("argv differs", _v135, _a135, _h_argv135, _p_argv135))
        except ValueError as _e135:
            _vbad135.append(("refused", _v135, _a135, str(_e135)))
check("fw verbs: every good argument list is taken by both tables, which build the same argv",
      not _vbad135, repr(_vbad135[:3]))
_vlax135 = []
for _v135, _cases135 in _BAD135.items():
    for _a135 in _cases135:
        for _side135, _fn135 in (("helper", _helper.validate), ("panel", _priv135.check_args)):
            if _takes135(lambda a, _f=_fn135, _v=_v135: _f(_v, list(a)), _a135):
                _vlax135.append((_side135, _v135, _a135))
check("fw verbs: every bad argument list (a word outside its set, injection, a count off) is refused by both",
      not _vlax135, repr(_vlax135[:4]))
check("fw verbs: a block goes to the TOP (`prepend`), names one protocol, and a family's source; both names none",
      _priv135.tool_argv("ufw-block-port", ["reject", "27015:27020", "udp", "v4", "blk"])[1:]
      == ["prepend", "reject", "proto", "udp", "from", "0.0.0.0/0", "to", "any", "port", "27015:27020",  # NOSONAR(S1313)
          "comment", "blk"]
      and _priv135.tool_argv("ufw-block-port", ["deny", "22000", "tcp", "v6", ""])[1:]
      == ["prepend", "deny", "proto", "tcp", "from", "::/0", "to", "any", "port", "22000"]
      and _priv135.tool_argv("ufw-block-port", ["deny", "22000", "tcp", "both", ""])[1:]
      == ["prepend", "deny", "proto", "tcp", "to", "any", "port", "22000"],
      repr(_priv135.tool_argv("ufw-block-port", ["deny", "22000", "tcp", "both", ""])))
check("fw verbs: the stored-rules read is a READ (no ufw_lock, ended with its caller); the rest change the host",
      not _core135._ufw_mutating("ufw-stored-rules") and "ufw-stored-rules" in _helper.READ_VERBS
      and all(_core135._ufw_mutating(v) for v in ("ufw-disable", "ufw-logging", "ufw-block-port",
                                                  "ufw-delete-block-port", "ufw-allow-port-family"))
      and not any(v in _helper.READ_VERBS for v in ("ufw-disable", "ufw-logging", "ufw-block-port")))

# ── the remote forms under bash/dash, against a stand-in ufw that records what it was given ──
_BIN135 = os.path.join(_TMP135, "bin")
os.makedirs(_BIN135, exist_ok=True)
_ARGS135 = os.path.join(_TMP135, "ufw-args")
with open(os.path.join(_BIN135, "ufw"), "w", encoding="utf-8") as _fh135:
    _fh135.write("#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > \"$UFW_ARGS\"\necho 'Rule added'\n")
# nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stand-in the suite runs itself
os.chmod(os.path.join(_BIN135, "ufw"), 0o700)


def _sh135(shell, cmd, env_extra=None):
    env = {"PATH": _BIN135 + ":/usr/bin:/bin", "UFW_ARGS": _ARGS135, "LC_ALL": "C.UTF-8"}
    env.update(env_extra or {})
    return _sp135.run([shell, "-c", cmd], capture_output=True, text=True, timeout=30, env=env,  # nosec B603 - fixed shells
                      check=False)


_twin135 = []
for _sh in _SHELLS135:
    for _v135, _a135 in (("ufw-block-port", ["reject", "27015:27020", "udp", "v4", "blk x"]),
                         ("ufw-allow-port-family", ["v6", "27015", "any", "a game"]),
                         ("ufw-logging", ["high"]), ("ufw-disable", []), ("ufw-default", ["deny", "routed"])):
        _r135 = _sh135(_sh, _priv135.remote_command(_v135, _a135))
        _got135 = open(_ARGS135, encoding="utf-8").read().splitlines() if os.path.exists(_ARGS135) else []
        if _r135.returncode != 0 or _got135 != [str(x) for x in _priv135.tool_argv(_v135, _a135)[1:]]:
            _twin135.append((_sh, _v135, _r135.returncode, _got135))
check("fw verbs (remote form, %s): ufw is handed exactly the validated argv, a comment with a space as one word"
      % "/".join(_SHELLS135), bool(_SHELLS135) and not _twin135, repr(_twin135[:2]))

# ── ufw-stored-rules: the helper's and the remote form print the same, or nothing ──
_STORE135 = os.path.join(_TMP135, "store")
os.makedirs(_STORE135, exist_ok=True)
_SPATHS135 = [os.path.join(_STORE135, n) for n in ("default", "ufw.conf", "user.rules", "user6.rules")]
_SBODY135 = ['IPV6=yes\nDEFAULT_INPUT_POLICY="DROP"\n# a \\n backslash and a %s\n', "LOGLEVEL=low",
             "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n", ""]   # NOSONAR(S1313)


def _write_store135(bodies):
    for p, b in zip(_SPATHS135, bodies):
        if b is None:
            if os.path.exists(p):
                os.unlink(p)
        else:
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(b)


def _helper_store135():
    import contextlib
    import io
    saved = _helper.FWA_STORED_PATHS
    _helper.FWA_STORED_PATHS = tuple(_SPATHS135)
    out, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = _helper.do_fwa_ufw_stored([], "")
    finally:
        _helper.FWA_STORED_PATHS = saved
    return rc, out.getvalue()


def _remote_store135(shell):
    cmd = _priv135.remote_command("ufw-stored-rules", [])
    for real, mine in zip(_priv135.FWA_STORED_PATHS, _SPATHS135):
        cmd = cmd.replace(real, mine)
    r = _sh135(shell, cmd)
    return r.returncode, r.stdout


_write_store135(_SBODY135)
_hs_ok135 = _helper_store135()
_marks135 = ["==> %s <==" % p for p in _SPATHS135]
_store_bad135 = []
for _sh in _SHELLS135:
    _rs_ok135 = _remote_store135(_sh)
    if _rs_ok135 != _hs_ok135:
        _store_bad135.append((_sh, "all files", _rs_ok135, _hs_ok135))
_write_store135(_SBODY135[:2] + [None, ""])
_hs_miss135 = _helper_store135()
for _sh in _SHELLS135:
    _rs_miss135 = _remote_store135(_sh)
    if _rs_miss135[0] == 0 or _rs_miss135[1]:
        _store_bad135.append((_sh, "a file missing", _rs_miss135))
check("ufw-stored-rules: the helper prints each file after its marker, a missing newline added, backslashes and "
      "% kept as written; one missing file is exit 1 and NOTHING on stdout",
      _hs_ok135[0] == 0 and [ln for ln in _hs_ok135[1].splitlines() if ln.startswith("==> ")] == _marks135
      and "# a \\n backslash and a %s\n" in _hs_ok135[1] and "LOGLEVEL=low\n==> " in _hs_ok135[1]
      and _hs_miss135 == (1, ""), repr((_hs_ok135, _hs_miss135)))
check("ufw-stored-rules (remote form, %s): prints exactly what the helper prints, and nothing with a file missing"
      % "/".join(_SHELLS135), bool(_SHELLS135) and not _store_bad135, repr(_store_bad135[:2]))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The reads
# ════════════════════════════════════════════════════════════════════════════════════════════════
# The tuples real ufw 0.36.2 stored for 31 rule shapes (ufw run in `unshare -rmn` over copies of its
# config), and the `ufw status numbered` it printed for them once enabled. Addresses are documentation
# and private ranges.
_U4_135 = """### tuple ### deny any any 0.0.0.0/0 any 10.0.0.0/8 in comment=70616e656c2d626c6f636b
### tuple ### deny tcp 27016:27020 0.0.0.0/0 any 0.0.0.0/0 in comment=626c6b
### tuple ### allow any any 0.0.0.0/0 any 0.0.0.0/0 in_tailscale0
### tuple ### limit tcp 22 0.0.0.0/0 any 0.0.0.0/0 in comment=5353482070616e656c
### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 OpenSSH - in
### tuple ### allow tcp 5000 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### allow any 53 0.0.0.0/0 any 0.0.0.0/0 out
### tuple ### allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 out
### tuple ### allow any any 0.0.0.0/0 any 0.0.0.0/0 out_tailscale0
### tuple ### allow tcp 22 0.0.0.0/0 any 192.168.1.0/24 in
### tuple ### route:allow tcp 8080 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### allow_log tcp 80 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### allow tcp 8081 0.0.0.0/0 any 0.0.0.0/0 in_eth0
### tuple ### allow any any 0.0.0.0/0 any 0.0.0.0/0 in_lo
### tuple ### deny tcp 25 0.0.0.0/0 any 0.0.0.0/0 out
### tuple ### allow udp 27015 0.0.0.0/0 any 0.0.0.0/0 in comment=67616d65207634
### tuple ### allow tcp 2222 203.0.113.5 any 0.0.0.0/0 in
"""  # NOSONAR(S1313) - ufw's stored rules, documentation and private addresses
_U6_135 = """### tuple ### deny any any ::/0 any 2001:db8::/32 in
### tuple ### reject udp 27021 ::/0 any ::/0 in
### tuple ### allow any any ::/0 any ::/0 in_tailscale0
### tuple ### limit tcp 22 ::/0 any ::/0 in comment=5353482070616e656c
### tuple ### allow tcp 22 ::/0 any ::/0 OpenSSH - in
### tuple ### allow tcp 5000 ::/0 any ::/0 in
### tuple ### allow any 53 ::/0 any ::/0 out
### tuple ### allow tcp 443 ::/0 any ::/0 out
### tuple ### allow any any ::/0 any ::/0 out_tailscale0
### tuple ### route:allow tcp 8080 ::/0 any ::/0 in
### tuple ### allow_log tcp 80 ::/0 any ::/0 in
### tuple ### allow tcp 8081 ::/0 any ::/0 in_eth0
### tuple ### allow any any ::/0 any ::/0 in_lo
### tuple ### deny tcp 25 ::/0 any ::/0 out
"""
_REAL_NUMBERED135 = """Status: active

     To                         Action      From
     --                         ------      ----
[ 1] Anywhere                   DENY IN     10.0.0.0/8                 # panel-block
[ 2] 27016:27020/tcp            DENY IN     Anywhere                   # blk
[ 3] Anywhere on tailscale0     ALLOW IN    Anywhere
[ 4] 22/tcp                     LIMIT IN    Anywhere                   # SSH panel
[ 5] OpenSSH                    ALLOW IN    Anywhere
[ 6] 5000/tcp                   ALLOW IN    Anywhere
[ 7] 53                         ALLOW OUT   Anywhere                   (out)
[ 8] 443/tcp                    ALLOW OUT   Anywhere                   (out)
[ 9] Anywhere                   ALLOW OUT   Anywhere on tailscale0     (out)
[10] 22/tcp                     ALLOW IN    192.168.1.0/24
[11] 8080/tcp                   ALLOW FWD   Anywhere
[12] 80/tcp                     ALLOW IN    Anywhere                   (log)
[13] 8081/tcp on eth0           ALLOW IN    Anywhere
[14] Anywhere on lo             ALLOW IN    Anywhere
[15] 25/tcp                     DENY OUT    Anywhere                   (out)
[16] 27015/udp                  ALLOW IN    Anywhere                   # game v4
[17] 203.0.113.5 2222/tcp       ALLOW IN    Anywhere
[18] Anywhere (v6)              DENY IN     2001:db8::/32
[19] 27021/udp (v6)             REJECT IN   Anywhere (v6)
[20] Anywhere (v6) on tailscale0 ALLOW IN    Anywhere (v6)
[21] 22/tcp (v6)                LIMIT IN    Anywhere (v6)              # SSH panel
[22] OpenSSH (v6)               ALLOW IN    Anywhere (v6)
[23] 5000/tcp (v6)              ALLOW IN    Anywhere (v6)
[24] 53 (v6)                    ALLOW OUT   Anywhere (v6)              (out)
[25] 443/tcp (v6)               ALLOW OUT   Anywhere (v6)              (out)
[26] Anywhere (v6)              ALLOW OUT   Anywhere (v6) on tailscale0 (out)
[27] 8080/tcp (v6)              ALLOW FWD   Anywhere (v6)
[28] 80/tcp (v6)                ALLOW IN    Anywhere (v6)              (log)
[29] 8081/tcp (v6) on eth0      ALLOW IN    Anywhere (v6)
[30] Anywhere (v6) on lo        ALLOW IN    Anywhere (v6)
[31] 25/tcp (v6)                DENY OUT    Anywhere (v6)              (out)
"""  # NOSONAR(S1313)
_real_rows135 = []
for _ln135 in _REAL_NUMBERED135.splitlines():
    _m135 = _fw135._UFW_NUMBERED_RE.match(_ln135)
    if _m135:
        _real_rows135.append({"num": _m135.group(1), "detail": _re135.sub(r"\s{2,}", "  ", _m135.group(2).strip())})
_mine135 = _fw135._fwa_stored_rows({"/etc/ufw/user.rules": _U4_135, "/etc/ufw/user6.rules": _U6_135})
check("stored rules: the tuples read into the rows real ufw listed for them, all 31, number and text "
      "(app profiles, route, log, interfaces, v4-only and v6-only rules, comments)",
      len(_real_rows135) == 31 and _mine135 == _real_rows135,
      repr([(a, b) for a, b in zip(_mine135, _real_rows135) if a != b][:2]))
check("stored rules: a malformed tuple is skipped as ufw skips it, and a bad comment's hex is no comment",
      _fw135._fwa_stored_rows({"/etc/ufw/user.rules": "### tuple ### allow tcp 22\n"
                               "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in comment=zz\n",  # NOSONAR(S1313)
                               "/etc/ufw/user6.rules": ""}) == [{"num": "1", "detail": "22/tcp  ALLOW IN  Anywhere"}])

_DEFAULT135 = ('# the defaults\nIPV6=yes\n#DEFAULT_INPUT_POLICY="ACCEPT"\nDEFAULT_INPUT_POLICY="DROP"\n'
               'DEFAULT_OUTPUT_POLICY="ACCEPT"\nDEFAULT_FORWARD_POLICY="REJECT"\n')
_CONF135 = "ENABLED=yes\nLOGLEVEL=medium\n"


def _stored_text135(default=_DEFAULT135, conf=_CONF135, u4="", u6=""):
    return "".join("==> %s <==\n%s" % (p, t) for p, t in zip(_priv135.FWA_STORED_PATHS, (default, conf, u4, u6)))


_VERBOSE_ON135 = ("Status: active\nLogging: on (high)\nDefault: reject (incoming), deny (outgoing), disabled (routed)\n"
                  "New profiles: skip\n\nTo                         Action      From\n")
_VERBOSE_OFF_LOG135 = "Status: active\nLogging: off\nDefault: deny (incoming), allow (outgoing), allow (routed)\n"
_VERBOSE_DE135 = ("Status: Aktiv\nProtokollierung: ein (hoch)\nVoreinstellung: ablehnen (eingehend), erlauben "
                  "(abgehend), deaktiviert (weitergeleitet)\nNeue Profile: überspringen\n\nZu   Aktion  Von\n"
                  "--   ------  ---\n")


def _settings_with135(status, stored=(0, None)):
    """remote_ufw_settings with its two reads answered: `status` (out, err, rc), `stored` (rc, text)."""
    def _rp(server, verb, args=(), **k):
        if verb == "ufw-status":
            return status
        if verb == "ufw-stored-rules":
            return (stored[1] or "", "", stored[0])
        return ("", "unexpected", 99)
    try:
        _p9_patch(_core135, "run_privileged", _rp)
        return _fw135.remote_ufw_settings(_NS135(is_local=False, auth_method="key", host="x", port=22))
    finally:
        _p9_restore_all()


_s_on135 = _settings_with135((_VERBOSE_ON135, "", 0), (0, _stored_text135()))
_s_log135 = _settings_with135((_VERBOSE_OFF_LOG135, "", 0), (0, _stored_text135()))
_s_inact135 = _settings_with135(("Status: inactive\n", "", 0), (0, _stored_text135()))
_s_de135 = _settings_with135((_VERBOSE_DE135, "", 0), (0, _stored_text135()))
_s_inact_unread135 = _settings_with135(("Status: inactive\n", "", 0), (1, ""))
check("settings read: while UFW is on, the LOADED values (C-locale `ufw status verbose`): defaults, routed "
      "disabled, logging on (high) / off",
      (_s_on135.get("incoming"), _s_on135.get("outgoing"), _s_on135.get("routed"), _s_on135.get("logging"),
       _s_on135.get("enabled"), _s_on135.get("ipv6")) == ("reject", "deny", "disabled", "high", True, True)
      and (_s_log135.get("routed"), _s_log135.get("logging")) == ("allow", "off"), repr((_s_on135, _s_log135)))
check("settings read: while UFW is off, the stored files as ufw reads them (a commented line inert, DROP = deny, "
      "REJECT = reject); a translated status falls back to them too, never a guess",
      (_s_inact135.get("enabled"), _s_inact135.get("incoming"), _s_inact135.get("outgoing"),
       _s_inact135.get("routed"), _s_inact135.get("logging")) == (False, "deny", "allow", "reject", "medium")
      and (_s_de135.get("enabled"), _s_de135.get("incoming"), _s_de135.get("logging")) == (True, "deny", "medium"),
      repr((_s_inact135, _s_de135)))
check("settings read: stored files that could not be read leave every value None (unknown), not a default",
      _s_inact_unread135.get("read_ok") is True and _s_inact_unread135.get("stored_ok") is False
      and all(_s_inact_unread135.get(k) is None for k in ("incoming", "outgoing", "routed", "logging", "ipv6")),
      repr(_s_inact_unread135))
_s_ts135 = _settings_with135(("", "SSH command timed out", -1))
_s_sudo135 = _settings_with135(("sudo: a password is required\n", "", 1))
_s_none135 = _settings_with135(("", "", 127))
check("settings read: tailscale/local's no-answer (-1) is unreadable, a sudo refusal says so, rc 127 is not installed",
      _s_ts135.get("read_ok") is False and _s_ts135.get("unreachable") is True
      and _s_sudo135.get("permission_denied") is True and _s_sudo135.get("read_ok") is False
      and _s_none135 == {"read_ok": True, "installed": False, "enabled": False}, repr((_s_ts135, _s_sudo135)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. The refusals, over a stand-in host
# ════════════════════════════════════════════════════════════════════════════════════════════════
class _Host135:
    """A host's UFW: its rules (rows as `ufw status numbered` prints them), policies, and what it was sent.

    `stored_rules` (tuple text) are what it lists from its files while off; `rc` answers every read
    (-1: tailscale/local's no answer); `ts` is (tailscale running, Tailscale SSH on); `sshd` the ports
    sshd serves (None: the read fails); `stick`: a change exits 0 and changes nothing.
    """

    def __init__(self, rules=(), enabled=True, incoming="deny", outgoing="allow", stored_rules="", rc=0,
                 ts=(False, False), sshd=("22",), stick=False, fail=()):
        self.rules, self.enabled, self.stored_rules, self.rc = list(rules), enabled, stored_rules, rc
        self.pol = {"incoming": incoming, "outgoing": outgoing, "routed": "deny"}
        self.logging, self.ts, self.sshd, self.stick, self.fail = "low", ts, sshd, stick, set(fail)
        self.sent = []

    def _status(self, kind):
        if not self.enabled:
            return "Status: inactive\n"
        head = "Status: active\n"
        if kind == "verbose":
            head += ("Logging: %s\nDefault: %s (incoming), %s (outgoing), %s (routed)\nNew profiles: skip\n"
                     % ("off" if self.logging == "off" else "on (%s)" % self.logging, self.pol["incoming"],
                        self.pol["outgoing"], self.pol["routed"]))
        return head + "\n     To  Action  From\n     --  ------  ----\n" + "".join(
            "[%2d] %s\n" % (i + 1, r) for i, r in enumerate(self.rules))

    def _stored(self):
        word = {"allow": "ACCEPT", "deny": "DROP", "reject": "REJECT"}
        default = "IPV6=yes\n" + "".join('DEFAULT_%s_POLICY="%s"\n' % (k, word[self.pol[d]]) for k, d in
                                         (("INPUT", "incoming"), ("OUTPUT", "outgoing"), ("FORWARD", "routed")))
        return _stored_text135(default, "LOGLEVEL=%s\n" % self.logging, self.stored_rules, "")

    def run(self, server, verb, args=(), **k):
        self.sent.append((verb, list(args)))
        if self.rc != 0:
            return ("", "SSH command timed out", self.rc)
        if verb == "ufw-status":
            return (self._status(args[0]), "", 0)
        if verb == "ufw-stored-rules":
            return (self._stored(), "", 0)
        if verb in self.fail:
            return ("ERROR: refused", "", 1)
        if not self.stick:
            self._apply(verb, list(args))
        return ("Rule added", "", 0)

    def _apply(self, verb, a):
        if verb == "ufw-default":
            self.pol[a[1]] = a[0]
        elif verb == "ufw-enable":
            self.enabled = True
        elif verb == "ufw-disable":
            self.enabled = False
        elif verb == "ufw-logging":
            self.logging = a[0]

    def changes(self):
        return [s for s in self.sent if s[0] not in ("ufw-status", "ufw-stored-rules")]


_REMOTE135 = _NS135(is_local=False, auth_method="key", host="192.0.2.10", port=22, id=None, name="h135")   # NOSONAR(S1313)
_TSREMOTE135 = _NS135(is_local=False, auth_method="tailscale", host="h.example.ts.net", port=22, id=None, name="t135")
_LOCAL135 = _NS135(is_local=True, auth_method="local", host="127.0.0.1", port=22, id=None, name="Panel")   # NOSONAR(S1313)


# Where the panel's SSH session to a remote comes from (a LAN address, so the LAN-source rule below is
# the panel's way in too; part136 holds a source outside it), and the viewer of a panel-host request.
_SRC135 = "192.168.1.50"   # NOSONAR(S1313) - a private address, never dialled
_VIEWER135 = "203.0.113.20"   # NOSONAR(S1313) - a documentation address


def _on135(host, fn, *a, served=False, panel_ports=(5000,), **kw):
    """Run fn(*a, **kw) against stand-in `host`; every host read is answered from it."""
    import ipaddress as _ip135
    try:
        _p9_arm(who="part135")
        _p9_patch(_core135, "run_privileged", host.run)
        _p9_patch(_hosts135, "_tailscale_conn_state", lambda s: host.ts)
        _p9_patch(_hosts135, "_sshd_current_ports",
                  lambda s: list(host.sshd) if host.sshd is not None else [])
        _p9_patch(_hosts135, "_tsiface_names", lambda s: ["tailscale0"])
        _p9_patch(_hosts135, "_r11a_sshd_off_tailnet", lambda s: False)
        _p9_patch(_fw135, "_panel_served_over_tailscale", lambda s: served and _core135.is_local_server(s))
        _p9_patch(_fw135, "_r31a_panel_web_ports",
                  lambda s, ts_running=None: [] if (served and ts_running) or not _core135.is_local_server(s)
                  else list(panel_ports))
        _p9_patch(_fw135, "_config_unreadable", lambda: False)
        _p9_patch(_cfg135, "load_config", lambda *x, **y: {"port": panel_ports[0] if panel_ports else 5000})
        _p9_patch(_cfg135, "bound_port", lambda: panel_ports[0] if panel_ports else None)
        _p9_patch(_hosts135, "_fwb_ssh_source", lambda s: _ip135.ip_address(_SRC135))
        _p9_patch(_fw135, "_fwb_tailscaled_port", lambda s: 41641)
        with _p9.test_request_context("/", environ_base={"REMOTE_ADDR": _VIEWER135}):
            return fn(*a, **kw)
    finally:
        _p9_restore_all()


def _deny_in135(rules, server=_REMOTE135, **kw):
    host = _Host135(rules=rules, incoming="allow", ts=kw.pop("ts", (False, False)))
    res = _on135(host, _fw135.remote_ufw_set_default, server, "incoming", "deny", **kw)
    return res, host.changes()


_SSH22 = "22/tcp  ALLOW IN  Anywhere"
_ok_in135, _ok_in_sent135 = _deny_in135([_SSH22])
check("default incoming deny: with a 22/tcp allow (the SSH port and the panel's) it is set, and read back",
      _ok_in135[0] is True and _ok_in_sent135 == [("ufw-default", ["deny", "incoming"])]
      and _ok_in135[2].get("incoming") == "deny", repr((_ok_in135, _ok_in_sent135)))
# Rules that must NOT count as a way in for SSH (each alone, so the change is refused and nothing sent).
_NOT_WAYS135 = {
    "no rule": [],
    "loopback": ["Anywhere on lo  ALLOW IN  Anywhere"],
    "docker bridge": ["Anywhere on docker0  ALLOW IN  Anywhere"],
    "a 127.0.0.1 source": ["22/tcp  ALLOW IN  127.0.0.1"],   # NOSONAR(S1313)
    "UDP only": ["22/udp  ALLOW IN  Anywhere"],
    "OUT": ["22/tcp  ALLOW OUT  Anywhere  (out)"],
    "FWD": ["22/tcp  ALLOW FWD  Anywhere"],
    "a DENY above the ALLOW": ["22/tcp  DENY IN  Anywhere", _SSH22],
    "another port": ["2222/tcp  ALLOW IN  Anywhere"],
    "tailscale0 with Tailscale down": ["Anywhere on tailscale0  ALLOW IN  Anywhere"],
}
_not135 = {k: _deny_in135(v) for k, v in _NOT_WAYS135.items()}
check("default incoming deny: refused, nothing sent, for every rule that is NO way in (%s)" % ", ".join(_not135),
      all(r[0] is False and sent == [] and "lock the panel or SSH out" in str(r[1]) for r, sent in _not135.values()),
      repr({k: (r[0], str(r[1])[:90], s) for k, (r, s) in _not135.items() if r[0] is not False or s}))
check("default incoming deny: ...and the refusal names what is missing (SSH's port)",
      "No rule lets SSH in (port 22/tcp)" in str(_not135["no rule"][0][1]), str(_not135["no rule"][0][1]))
_ways135 = {
    "a rate limit": ["22/tcp  LIMIT IN  Anywhere"],
    "OpenSSH": ["OpenSSH  ALLOW IN  Anywhere"],
    "an auto-block DENY above": ["Anywhere  DENY IN  198.51.100.9", _SSH22],   # NOSONAR(S1313)
    "a LAN source": ["22/tcp  ALLOW IN  192.168.1.0/24"],
}
_yes135 = {k: _deny_in135(v) for k, v in _ways135.items()}
check("default incoming deny: ...set where a real way in exists (%s) — the positive controls" % ", ".join(_yes135),
      all(r[0] is True and sent == [("ufw-default", ["deny", "incoming"])] for r, sent in _yes135.values()),
      repr({k: (r[0], str(r[1])[:80]) for k, (r, _s) in _yes135.items()}))
# SSH reachable over the tailnet, but the panel dials this key-auth host on its public port 22.
_TS0 = "Anywhere on tailscale0  ALLOW IN  Anywhere"
_ts_only135 = _deny_in135([_TS0], ts=(True, False))
_ts_rem135 = _deny_in135([_TS0], server=_TSREMOTE135, ts=(True, False))
_ts_ssh135 = _deny_in135([], server=_TSREMOTE135, ts=(True, True))
check("default incoming deny: the PANEL's own way in counts too — a key host it dials on 22 with only a tailscale0 "
      "allow is refused; a host it reaches over Tailscale with that allow, or with Tailscale SSH, is set",
      _ts_only135[0][0] is False and "SSH port the panel connects on (22/tcp)" in str(_ts_only135[0][1])
      and _ts_rem135[0][0] is True and _ts_ssh135[0][0] is True,
      repr((_ts_only135, _ts_rem135[0][:2], _ts_ssh135[0][:2])))
# The panel's own host: its web port.
_loc_no135 = _deny_in135([_SSH22], server=_LOCAL135)
_loc_yes135 = _deny_in135([_SSH22, "5000/tcp  ALLOW IN  Anywhere"], server=_LOCAL135)
_loc_ts135 = _deny_in135([_SSH22, _TS0], server=_LOCAL135, served=True, ts=(True, False))
_loc_tsno135 = _deny_in135([_SSH22], server=_LOCAL135, served=True, ts=(True, False))
check("default incoming deny (panel host): refused without the panel's web port open, set with it; published "
      "over Tailscale Serve it needs the tailscale0 allow instead",
      _loc_no135[0][0] is False and "web port 5000/tcp" in str(_loc_no135[0][1]) and _loc_yes135[0][0] is True
      and _loc_ts135[0][0] is True and _loc_tsno135[0][0] is False
      and "Tailscale Serve" in str(_loc_tsno135[0][1]),
      repr((_loc_no135[0][:2], _loc_yes135[0][:2], _loc_ts135[0][:2], _loc_tsno135[0][:2])))
_reject135 = _on135(_Host135(rules=[], incoming="allow"), _fw135.remote_ufw_set_default, _REMOTE135, "incoming",
                    "reject")
check("default incoming REJECT is held to the same check as deny", _reject135[0] is False, repr(_reject135))

# ── unknown state refuses ──
_unk135 = {}
for _what135, _call135 in (("default", lambda: _fw135.remote_ufw_set_default(_REMOTE135, "incoming", "allow")),
                           ("on", lambda: _fw135.remote_ufw_set_enabled(_REMOTE135, True)),
                           ("off", lambda: _fw135.remote_ufw_set_enabled(_REMOTE135, False, confirm=True)),
                           ("logging", lambda: _fw135.remote_ufw_set_logging(_REMOTE135, "low"))):
    _h135 = _Host135(rules=[_SSH22], enabled=False, rc=-1)
    _unk135[_what135] = (_on135(_h135, _call135), _h135.changes())
check("an unreadable firewall (tailscale/local's -1) refuses every settings change, and sends nothing",
      all(r[0] is False and "Couldn't read the firewall" in str(r[1]) and sent == [] for r, sent in _unk135.values()),
      repr({k: (v[0][0], str(v[0][1])[:60], v[1]) for k, v in _unk135.items()}))


def _raise135(*a, **k):
    raise ConnectionError("refused")


try:
    _p9_patch(_core135, "run_privileged", _raise135)
    try:
        _fw135.remote_ufw_set_default(_REMOTE135, "incoming", "deny")
        _raised135 = False
    except ConnectionError:
        _raised135 = True
finally:
    _p9_restore_all()
check("a paramiko host that is down RAISES out of a settings change (the route answers it as unreachable)",
      _raised135)

# ── turning UFW on: the stored rules while it is off ──
_ST_SSH = "### tuple ### limit tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n"   # NOSONAR(S1313)
_ST_LO = "### tuple ### allow any any 0.0.0.0/0 any 0.0.0.0/0 in_lo\n"   # NOSONAR(S1313)
_h_on_ok135 = _Host135(enabled=False, stored_rules=_ST_SSH)
_r_on_ok135 = _on135(_h_on_ok135, _fw135.remote_ufw_set_enabled, _REMOTE135, True)
_h_on_no135 = _Host135(enabled=False, stored_rules=_ST_LO)
_r_on_no135 = _on135(_h_on_no135, _fw135.remote_ufw_set_enabled, _REMOTE135, True)
_h_on_out135 = _Host135(enabled=False, stored_rules=_ST_SSH, outgoing="deny")
_r_on_out135 = _on135(_h_on_out135, _fw135.remote_ufw_set_enabled, _REMOTE135, True)
check("turn on: refused while the STORED rules let no SSH in (an `allow in on lo` is none), set with a stored "
      "22/tcp limit; a stored outgoing deny needs DNS/HTTP/HTTPS out first",
      _r_on_no135[0] is False and _h_on_no135.changes() == [] and "lock the panel or SSH out" in str(_r_on_no135[1])
      and _r_on_ok135[0] is True and _h_on_ok135.changes() == [("ufw-enable", [])]
      and _r_on_out135[0] is False and "Nothing allows DNS out" in str(_r_on_out135[1])
      and _h_on_out135.changes() == [],
      repr((_r_on_no135[:2], _r_on_ok135[:2], _r_on_out135[:2])))
_h_off_no135 = _Host135(rules=[_SSH22])
_r_off_no135 = _on135(_h_off_no135, _fw135.remote_ufw_set_enabled, _REMOTE135, False)
_h_off_yes135 = _Host135(rules=[_SSH22])
_r_off_yes135 = _on135(_h_off_yes135, _fw135.remote_ufw_set_enabled, _REMOTE135, False, confirm=True)
_h_off_str135 = _Host135(rules=[_SSH22])
_r_off_str135 = _on135(_h_off_str135, _fw135.remote_ufw_set_enabled, _REMOTE135, False, confirm="true")
check("turn off: refused without a confirmation (a string \"true\" is not one), sent with it, and the answer says "
      "the host now accepts every connection",
      _r_off_no135[0] is False and _h_off_no135.changes() == [] and _r_off_str135[0] is False
      and _h_off_str135.changes() == [] and _r_off_yes135[0] is True
      and _h_off_yes135.changes() == [("ufw-disable", [])] and "accepts every connection" in str(_r_off_yes135[1]),
      repr((_r_off_no135[:2], _r_off_yes135[:2])))
_h_stick135 = _Host135(rules=[_SSH22], stick=True)
_r_stick135 = _on135(_h_stick135, _fw135.remote_ufw_set_enabled, _REMOTE135, False, confirm=True)
_h_stick2_135 = _Host135(rules=[_SSH22], incoming="allow", stick=True)
_r_stick2_135 = _on135(_h_stick2_135, _fw135.remote_ufw_set_default, _REMOTE135, "incoming", "deny")
check("a change ufw answered 0 to but that did not take is reported as failed, from the read-back",
      _r_stick135[0] is False and _r_stick2_135[0] is False and "still reads" in str(_r_stick2_135[1]),
      repr((_r_stick135[:2], _r_stick2_135[:2])))

# ── outgoing ──
_OUTS = ["53  ALLOW OUT  Anywhere  (out)", "80/tcp  ALLOW OUT  Anywhere  (out)", "443/tcp  ALLOW OUT  Anywhere  (out)"]


def _deny_out135(rules, server=_REMOTE135, confirm=True):
    host = _Host135(rules=[_SSH22] + rules)
    return _on135(host, _fw135.remote_ufw_set_default, server, "outgoing", "deny", confirm=confirm), host.changes()


_o_noconf135 = _deny_out135(_OUTS, confirm=False)
_o_nodns135 = _deny_out135(_OUTS[1:])
_o_dnstcp135 = _deny_out135(["53/udp  ALLOW OUT  Anywhere  (out)"] + _OUTS[1:])
_o_shadow135 = _deny_out135(["53  DENY OUT  Anywhere  (out)"] + _OUTS)
_o_dest135 = _deny_out135(["198.51.100.1 53  ALLOW OUT  Anywhere  (out)"] + _OUTS[1:])   # NOSONAR(S1313)
_o_ok135 = _deny_out135(_OUTS)
check("default outgoing deny: refused without confirmation, without DNS out (or DNS over UDP only, behind a DENY "
      "OUT, or to one resolver only), set with DNS, HTTP and HTTPS allowed out",
      all(r[0] is False and s == [] for r, s in (_o_noconf135, _o_nodns135, _o_dnstcp135, _o_shadow135, _o_dest135))
      and "confirmation" in str(_o_noconf135[0][1]) and "Nothing allows DNS out (53/udp)" in str(_o_nodns135[0][1])
      and "53/tcp" in str(_o_dnstcp135[0][1])
      and _o_ok135[0][0] is True and _o_ok135[1] == [("ufw-default", ["deny", "outgoing"])],
      repr([str(x[0][1])[:100] for x in (_o_noconf135, _o_nodns135, _o_dnstcp135, _o_shadow135, _o_dest135, _o_ok135)]))
_o_local135 = _deny_out135(_OUTS, server=_LOCAL135)
_o_local_ok135 = _deny_out135(_OUTS + ["22/tcp  ALLOW OUT  Anywhere  (out)"], server=_LOCAL135)
check("default outgoing deny (panel host): its SSH out to every remote it manages is needed as well",
      _o_local135[0][0] is False and "Nothing allows the panel out to p9-host on SSH port 22/tcp" in str(_o_local135[0][1])
      and _o_local_ok135[0][0] is True, repr((str(_o_local135[0][1])[:200], _o_local_ok135[0][:2])))
_routed135 = _on135(_Host135(rules=[]), _fw135.remote_ufw_set_default, _REMOTE135, "routed", "reject")
check("routed policy: governs only traffic passing through, so it is set with no way-in check",
      _routed135[0] is True, repr(_routed135))

# ── port blocks ──
def _block135(spec, proto="tcp", family="both", action="deny", server=_REMOTE135, sshd=("22",), **kw):
    host = _Host135(rules=[_SSH22], sshd=sshd, fail=kw.pop("fail", ()))
    res = _on135(host, _fw135.remote_ufw_block_port, server, spec, proto, family, action, "blk", **kw)
    return res, host.changes()


_b_ssh135 = _block135("20:30")
_b_ssh2135 = _block135("2200:2300", sshd=("2222",))
_b_unread135 = _block135("27015", sshd=None)
_b_panel135 = _block135("4990:5010", server=_LOCAL135, panel_ports=(5000,))
_b_ts135 = _block135("41000:42000", proto="udp")
_b_udp22_135 = _block135("22", proto="udp")
_b_ts_tcp135 = _block135("41641", proto="tcp")
check("port block: refused on SSH's port (in a range, and where sshd serves 2222), with sshd unreadable, on the "
      "panel's web port and on Tailscale's UDP port — nothing sent",
      all(r[0] is False and s == [] for r, s in (_b_ssh135, _b_ssh2135, _b_unread135, _b_panel135, _b_ts135))
      and "Port 22 is SSH's" in str(_b_ssh135[0][1]) and "Port 2222 is SSH's" in str(_b_ssh2135[0][1])
      and "Couldn't read which ports SSH" in str(_b_unread135[0][1]) and "web port" in str(_b_panel135[0][1])
      and "41641/udp" in str(_b_ts135[0][1]),
      repr([str(x[0][1])[:70] for x in (_b_ssh135, _b_ssh2135, _b_unread135, _b_panel135, _b_ts135)]))
check("port block: ...UDP on 22 (sshd is TCP) and TCP on 41641 are blocked (positive controls)",
      _b_udp22_135[0][0] is True and _b_udp22_135[1] == [("ufw-block-port", ["deny", "22", "udp", "both", "blk"])]
      and _b_ts_tcp135[0][0] is True, repr((_b_udp22_135, _b_ts_tcp135[0])))
_b_both135 = _block135("27015:27020", proto="both", family="v6", action="reject")
check("port block: both protocols is one rule each (a range needs one), with the family and action asked for",
      _b_both135[0][0] is True and _b_both135[1] == [
          ("ufw-block-port", ["reject", "27015:27020", "tcp", "v6", "blk"]),
          ("ufw-block-port", ["reject", "27015:27020", "udp", "v6", "blk"])], repr(_b_both135))


class _HalfHost135(_Host135):
    """The UDP half of a block fails; the TCP half goes in."""

    def run(self, server, verb, args=(), **k):
        if verb == "ufw-block-port" and list(args)[2] == "udp":
            self.sent.append((verb, list(args)))
            return ("ERROR: half", "", 1)
        return super().run(server, verb, args, **k)


_hh135 = _HalfHost135(rules=[_SSH22])
_hr135 = _on135(_hh135, _fw135.remote_ufw_block_port, _REMOTE135, "27015", "both", "both", "deny", "")
check("port block: when the second protocol fails the first is taken out again, and the answer is ufw's",
      _hr135[0] is False and "ERROR: half" in str(_hr135[1]) and _hh135.changes() == [
          ("ufw-block-port", ["deny", "27015", "tcp", "both", ""]),
          ("ufw-block-port", ["deny", "27015", "udp", "both", ""]),
          ("ufw-delete-block-port", ["deny", "27015", "tcp", "v4"])], repr((_hr135, _hh135.changes())))
_b_badspec135 = [_block135(s)[0][0] for s in ("27015:27015", "abc", "0", "22;id")]
check("port block: a spec that is not a port or a lo<hi range is refused before anything is read",
      _b_badspec135 == [False] * 4, repr(_b_badspec135))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. The routes
# ════════════════════════════════════════════════════════════════════════════════════════════════
_SETTINGS135 = {"read_ok": True, "installed": True, "enabled": True, "incoming": "deny", "outgoing": "allow",
                "routed": "disabled", "logging": "low", "ipv6": True}
_rcalls135 = []
_routes135 = {}
try:
    _p9_arm(who="part135")
    _p9_patch(_fw135, "remote_ufw_settings", lambda r: dict(_SETTINGS135))
    _p9_patch(_fw135, "remote_ufw_set_default", lambda r, d, p, confirm=False: (
        _rcalls135.append(("default", d, p, confirm)), (False, _fw135._FWA_UNREAD, None))[1])
    _p9_patch(_fw135, "remote_ufw_set_enabled", lambda r, on, confirm=False: (
        _rcalls135.append(("enabled", on, confirm)), (True, "ok", dict(_SETTINGS135)))[1])
    _p9_patch(_fw135, "remote_ufw_set_logging", lambda r, lv: (_rcalls135.append(("logging", lv)), (True, "ok", None))[1])
    _p9_patch(_fw135, "remote_ufw_block_port", lambda r, *a: (_rcalls135.append(("block",) + a), (True, "blocked"))[1])
    _A135 = _p9_client(P9_ADMIN)
    _base135 = "/api/remote/%d/firewall/" % P9_HOST
    _routes135["get"] = _A135.get(_base135 + "settings")
    _routes135["default"] = _A135.post(_base135 + "settings", json={"setting": "incoming", "value": "deny"})
    _routes135["off"] = _A135.post(_base135 + "settings", json={"setting": "enabled", "value": False, "confirm": True})
    _routes135["offstr"] = _A135.post(_base135 + "settings", json={"setting": "enabled", "value": "false",
                                                                   "confirm": True})
    _routes135["confbad"] = _A135.post(_base135 + "settings", json={"setting": "enabled", "value": False,
                                                                    "confirm": "yes"})
    _routes135["junk"] = _A135.post(_base135 + "settings", json={"setting": "rm -rf", "value": "x; id"})
    _routes135["block"] = _A135.post(_base135 + "block-port", json={"port": "27015:27020", "protocol": "udp",
                                                                    "family": "v4", "action": "reject"})
    _routes135["blockjunk"] = _A135.post(_base135 + "block-port", json={"port": "1;id", "protocol": "x",
                                                                        "family": "y", "action": "z"})
    _V135 = _p9_client(P9_VIEWER)
    _routes135["viewer"] = [_V135.get(_base135 + "settings").status_code,
                            _V135.post(_base135 + "settings", json={"setting": "logging", "value": "off"}).status_code,
                            _V135.post(_base135 + "block-port", json={"port": "27015"}).status_code]
    _a_junk135 = _p9_audit("remote_ufw_settings")
    _a_block135 = _p9_audit("remote_port_block")
finally:
    _p9_restore_all()
_rj135 = {k: (v.status_code, v.get_json(silent=True)) for k, v in _routes135.items() if k != "viewer"}
check("routes: GET settings answers the read; POST passes the setting, value and a JSON-boolean confirm down",
      _rj135["get"] == (200, _SETTINGS135) and _rj135["default"][1]["success"] is False
      and ("default", "incoming", "deny", False) in _rcalls135 and ("enabled", False, True) in _rcalls135
      and _rj135["off"][1]["settings"] == _SETTINGS135, repr((_rj135, _rcalls135)))
check("routes: `confirm: \"yes\"` is a 400; `enabled: \"false\"` and an unknown setting change nothing",
      _rj135["confbad"][0] == 400 and _rj135["offstr"][1]["success"] is False
      and _rj135["junk"][1]["success"] is False
      and not any(c[0] == "enabled" and c[1] == "false" for c in _rcalls135), repr((_rj135, _rcalls135)))
check("routes: the audit row names validated values only — a junk setting is fixed text, never the request's",
      _a_junk135.target and _a_junk135.target.endswith(":(not a setting)") and _a_junk135.detail == "(not a value)"
      and "rm -rf" not in (_a_junk135.target + _a_junk135.detail), repr(_a_junk135))
check("routes: block-port passes the spec, protocol, family and action; its audit row says them, validated",
      ("block", "27015:27020", "udp", "v4", "reject", "") in _rcalls135 and _rj135["block"][1]["success"] is True
      and _a_block135.target and _a_block135.target.endswith(":(not a port)/(not a protocol)")
      and _a_block135.detail == "(not a value) (not a value)", repr((_rcalls135, _a_block135)))
check("routes: an account without MANAGE_REMOTES reaches neither new route (GET or POST)",
      all(st in (302, 403) for st in _routes135["viewer"]), repr(_routes135["viewer"]))
# A DELEGATED host admin: MANAGE_REMOTES through a group whose grant covers the panel's own host and
# a remote. The panel host's firewall guards the panel itself, so its settings and blocks stay
# superadmin-only (get_host_remote), as every other firewall action there is; on the remote the same
# account is let through (positive control).
from panel.db.models import Group as _Group135, RemoteServer as _RS135, User as _User135, db as _db135
from panel.security import auth as _auth135
with _p9.app_context():
    _g135 = _Group135(name="p135_hostadmins", description="", is_default=False)
    _g135.set_permissions([_auth135.MANAGE_REMOTES])
    _g135.servers.append(_db135.session.get(_RS135, P9_LOCAL))
    _g135.servers.append(_db135.session.get(_RS135, P9_HOST))
    _db135.session.add(_g135)
    _d135 = _User135(username="p135_delegate", password_hash=_auth135.hash_password("x" + "Q7!long-p135-pw"),
                     display_name="Delegate", is_superadmin=False, is_active=True)
    _d135.groups.append(_g135)
    _db135.session.add(_d135)
    _db135.session.commit()
    _D135 = _d135.id
_deleg135 = {}
try:
    _p9_arm(who="part135")
    _p9_patch(_fw135, "remote_ufw_settings", lambda r: dict(_SETTINGS135))
    _p9_patch(_fw135, "remote_ufw_set_enabled", lambda r, on, confirm=False: (True, "ok", dict(_SETTINGS135)))
    _p9_patch(_fw135, "remote_ufw_block_port", lambda r, *a: (True, "blocked"))
    from panel.routes import remote_vps as _rv135
    _p9_patch(_rv135, "remote_ufw_open_port", lambda r, *a, **k: (True, "opened"))
    _p9_patch(_fw135, "fwb_open_shadow_note", lambda *a: None)
    _C135 = _p9_client(_D135)
    for _hk135, _hid135 in (("panel host", P9_LOCAL), ("remote", P9_HOST)):
        _b135 = "/api/remote/%d/firewall/" % _hid135
        _deleg135[_hk135] = [
            _C135.get(_b135 + "settings").status_code,
            _C135.post(_b135 + "settings", json={"setting": "enabled", "value": False, "confirm": True}).status_code,
            _C135.post(_b135 + "block-port", json={"port": "27015"}).status_code,
            _C135.post(_b135 + "open", json={"port": 27015}).status_code]
finally:
    _p9_restore_all()
check("routes: a DELEGATED MANAGE_REMOTES admin whose grant covers the panel host is refused (403) its firewall "
      "settings and blocks there, as /firewall/open is; on a remote the same account is let through",
      _deleg135.get("panel host") == [403, 403, 403, 403]
      and _deleg135.get("remote") == [200, 200, 200, 200], repr(_deleg135))
_RV_SRC135 = _read135("panel", "routes", "remote_vps.py")
_settings_src135 = _RV_SRC135[_RV_SRC135.index("def _register_firewall_settings(app):"):
                              _RV_SRC135.index("def _register_ssh_settings(app):")]
check("routes: both new views carry the firewall routes' own guards (login, MANAGE_REMOTES, get_host_remote: the "
      "panel's own host superadmin-only)",
      _settings_src135.count("@login_required") == 2 and _settings_src135.count("@permission_required(MANAGE_REMOTES)") == 2
      and _settings_src135.count("remote = get_host_remote(remote_id)") == 2)

# ── the range block ──
_rb_calls135, _rb135 = [], {}
_RB_SRC135 = {"src": "198.51.100.77", "rc": 0}   # NOSONAR(S1313) - a documentation address, never dialled


def _rb_cmd135(server, cmd, **k):
    if "SSH_CONNECTION" in cmd:
        return ((_RB_SRC135["src"] + " 51515 192.0.2.10 22\n") if _RB_SRC135["rc"] == 0 else "", "",   # NOSONAR(S1313)
                _RB_SRC135["rc"])
    return ("", "", 1)


try:
    _p9_arm(who="part135")
    _p9_patch(_rs135, "tailnet_exempt_ips", lambda remote, ips: set())
    _p9_patch(_rs135, "_whitelisted", lambda ip: False)
    _p9_patch(_rs135, "_whitelist_networks", lambda: [__import__("ipaddress").ip_network("203.0.113.64/26")])  # NOSONAR(S1313)
    _p9_patch(_rs135, "remote_ufw_deny_ip", lambda r, ip: (_rb_calls135.append(ip), (True, "ok"))[1])
    _p9_patch(_rs135, "_follow_in_panel_gate", lambda remote, ok: None)
    _p9_patch(_core135, "run_command", _rb_cmd135)
    _p9_patch(_rs135, "_fwb_panel_host_addrs", lambda: set())
    _A135 = _p9_client(P9_ADMIN)
    _burl135 = "/api/remote/%d/security/block" % P9_HOST
    for _k135, _ip135 in (("tailnet", "100.64.0.0/9"), ("whitelist", "203.0.113.0/24"), ("mine", "127.0.0.0/8"),  # NOSONAR(S1313)
                          ("mine1", "127.0.0.1"), ("source", "198.51.100.0/24"), ("v6tail", "fd7a:115c::/32"),  # NOSONAR(S1313)
                          ("ok", "198.51.100.200/29"), ("okhost", "192.0.2.77/24"), ("all", "0.0.0.0/0"),  # NOSONAR(S1313)
                          ("zone", "fe80::/64%eth0"), ("ok6", "2001:db8:aa::/48")):
        _rb135[_k135] = _A135.post(_burl135, json={"ip": _ip135}).get_json(silent=True) or {}
    _RB_SRC135["rc"] = -1
    _rb135["unread"] = _A135.post(_burl135, json={"ip": "192.0.2.128/25"}).get_json(silent=True) or {}  # NOSONAR(S1313)
    _a_rb135 = _p9_audit("ufw_block")
finally:
    _p9_restore_all()
_rbm135 = {k: (v.get("success"), str(v.get("message", ""))[:200]) for k, v in _rb135.items()}
check("range block: refused reaching into the tailnet (v4 and v6) or the whitelist, covering the viewer's own "
      "address (one address too) or the panel's source, or with that source unread",
      all(_rb135[k].get("success") is False for k in ("tailnet", "whitelist", "mine", "mine1", "source", "v6tail",
                                                         "unread"))
      and "Tailscale" in _rbm135["tailnet"][1] and "whitelist" in _rbm135["whitelist"][1]
      and "your own address" in _rbm135["mine1"][1] and "the panel connects to this host from" in _rbm135["source"][1]
      and "Couldn't read the address" in _rbm135["unread"][1], repr(_rbm135))
check("range block: a range clear of all of those is blocked (the deny masks it: 192.0.2.77/24 -> 192.0.2.0/24), "
      "IPv6 too; every address and a zone id never reach the deny",
      _rb135["ok"].get("success") is True and _rb135["okhost"].get("success") is True
      and _rb135["ok6"].get("success") is True and _rb135["zone"].get("success") is False
      and _rb135["all"].get("success") is False
      and _rb_calls135 == ["198.51.100.200/29", "192.0.2.0/24", "2001:db8:aa::/48"]  # NOSONAR(S1313)
      and _hosts135.fwa_block_target("192.0.2.77/24") == "192.0.2.0/24"  # NOSONAR(S1313)
      and _hosts135.fwa_block_target("2001:db8:aa::5/48") == "2001:db8:aa::/48"
      and _hosts135.fwa_block_target("192.0.2.7/32") == "192.0.2.7"  # NOSONAR(S1313)
      and _hosts135.fwa_block_target("fe80::/64%eth0") is None
      and _a_rb135.target == "192.0.2.128/25", repr((_rb_calls135, _rbm135, _a_rb135)))  # NOSONAR(S1313)
_deny_all135 = _on135(_Host135(), _hosts135.remote_ufw_deny_ip, _REMOTE135, "0.0.0.0/0")  # NOSONAR(S1313)
check("range block: every address (/0) is refused by the deny itself", _deny_all135[0] is False, repr(_deny_all135))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. The settings row's script, in node
# ════════════════════════════════════════════════════════════════════════════════════════════════
_FWJS135 = _read135("static", "js", "remote_firewall.js")
_DOM135 = r"""
function el(id, extra) { return Object.assign({id: id, value: '', disabled: false, hidden: false, className: '',
  textContent: '', innerHTML: '', options: [], children: [],
  insertBefore(o) { o.parent = this; this.options.unshift(o); },
  querySelector() { return null; }}, extra || {}); }
function sel(id, vals) { const s = el(id); vals.forEach(v => s.options.push({value: v, textContent: v, parent: s,
  remove() { s.options.splice(s.options.indexOf(this), 1); }})); s.value = vals[0]; return s; }
const els = {'fw-settings': el('fw-settings'), 'fw-set-incoming': sel('fw-set-incoming', ['allow','deny','reject']),
  'fw-set-outgoing': sel('fw-set-outgoing', ['allow','deny','reject']), 'fw-set-routed': sel('fw-set-routed', ['allow','deny','reject']),
  'fw-set-logging': sel('fw-set-logging', ['off','low','medium','high','full']), 'fw-set-routed-wrap': el('w'),
  'fw-set-enabled': el('b'), 'fw-set-enabled-label': el('l'), 'fw-settings-msg': el('m')};
global.document = {getElementById: id => els[id] || null, createElement: () => ({value: '', textContent: '',
  remove() { const s = this.parent; s.options.splice(s.options.indexOf(this), 1); }})};
global.t = s => s; global.esc = s => String(s); global.MOUNT = ''; global.remoteId = 7;
let dialogs = [], posts = [], reads = 0;
global.confirmDialog = o => dialogs.push(o);
global.refreshFirewall = () => {};
global.fetch = (url, o) => { if (o && o.method === 'POST') posts.push(JSON.parse(o.body)); else reads++;
  return Promise.resolve({json: () => Promise.resolve({success: true, message: 'ok', settings: null})}); };
"""
_out135 = _node47(_DOM135 + (
    "const settle = async () => { for (let i = 0; i < 6; i++) await new Promise(r => setImmediate(r)); };\n"
    + "".join(_m.group(0) + "\n" for _m in _re135.finditer(r"(?m)^var _(?:fwSettings|FW_SETTING_KEYS) = .*;$",
                                                            _FWJS135))
    + "".join(_cut47(_FWJS135, h) + "\n" for h in (
        "function refreshFwSettings(", "function _fwSelectValue(", "function _fwPaintSettings(",
        "var _FW_SETTING_COPY =", "function fwSettingChange(", "function fwToggleEnabled(", "function _fwPostSetting("))
    + "(async () => { const out = {};\n"
    "  _fwPaintSettings({read_ok: true, installed: true, enabled: true, incoming: 'allow', outgoing: 'allow',\n"
    "    routed: 'disabled', logging: null});\n"
    "  out.paint = [els['fw-set-incoming'].value, els['fw-set-incoming'].disabled, els['fw-set-logging'].value,\n"
    "    els['fw-set-logging'].disabled, els['fw-set-logging'].options[0].value, els['fw-set-routed-wrap'].hidden,\n"
    "    els['fw-set-enabled-label'].textContent, els['fw-set-enabled'].className];\n"
    "  els['fw-set-incoming'].value = 'deny'; fwSettingChange('incoming', els['fw-set-incoming']);\n"
    "  out.asked = [els['fw-set-incoming'].value, dialogs.length, posts.length, dialogs[0] && dialogs[0].confirmClass,\n"
    "    dialogs[0] && dialogs[0].bodyText.indexOf('Drop every incoming') === 0];\n"
    "  dialogs[0].onConfirm(); await settle();\n"
    "  out.sent = posts.slice();\n"
    "  fwToggleEnabled(); out.toggle = [dialogs[1].title, dialogs[1].confirmClass, posts.length];\n"
    "  dialogs[1].onConfirm(); await settle(); out.sent2 = posts[posts.length - 1];\n"
    "  _fwPaintSettings({read_ok: false, unreachable: true});\n"
    "  out.unread = [els['fw-set-incoming'].disabled, els['fw-set-incoming'].value, els['fw-set-enabled'].disabled];\n"
    "  els['fw-set-outgoing'].value = 'deny'; fwSettingChange('outgoing', els['fw-set-outgoing']);\n"
    "  out.unreadAsk = dialogs.length;\n"
    "  refreshFwSettings(); await settle(); out.reads = reads;\n"
    "  console.log(JSON.stringify(out)); })();\n"))
check("settings row (node): a read paints each select, an unknown value (logging null) is an added Unknown and "
      "disabled, routed hidden where ufw says disabled, the button says Turn off for a firewall that is on",
      bool(_out135) and _out135.get("paint") == ["allow", False, "", True, "", True, "Turn off",
                                                 "btn btn-sm w-100 btn-outline-danger"], repr(_out135))
check("settings row (node): a change puts the select back to what is in force and only ASKS (a red Apply for a "
      "deny); nothing is sent until yes, then exactly {setting, value, confirm: true}",
      bool(_out135) and _out135.get("asked") == ["allow", 1, 0, "btn-danger", True]
      and _out135.get("sent") == [{"setting": "incoming", "value": "deny", "confirm": True}], repr(_out135))
check("settings row (node): turning off asks with the off dialog, sends enabled false on yes; an unread firewall "
      "disables every control and asks nothing",
      bool(_out135) and _out135.get("toggle") == ["Turn the firewall off", "btn-danger", 1]
      and _out135.get("sent2") == {"setting": "enabled", "value": False, "confirm": True}
      and _out135.get("unread") == [True, "", True] and _out135.get("unreadAsk") == 2
      and _out135.get("reads") == 1, repr(_out135))
check("settings row: the rules' refresh reads the settings too, and the settings markup carries every control "
      "the script paints",
      "refreshFwSettings();" in _cut47(_FWJS135, "function refreshFirewall(")
      and all('id="%s"' % i in _read135("templates", "_firewall_panel.html") for i in (
          "fw-settings", "fw-set-enabled", "fw-set-enabled-label", "fw-settings-msg", "block-port",
          "block-proto", "block-action", "block-comment"))
      and all('fw_setting("%s"' % k in _read135("templates", "_firewall_panel.html")
              for k in ("incoming", "outgoing", "routed", "logging"))
      and 'id="fw-set-routed-wrap" hidden' in _read135("templates", "_firewall_panel.html")
      and all('fw_family_select("%s")' % i in _read135("templates", "_firewall_panel.html")
              for i in ("new-family", "block-family")))

check("part135: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP135_START, repr(_P9_TRIPPED[_TRIP135_START:][:3]))
_shutil135.rmtree(_TMP135, ignore_errors=True)
