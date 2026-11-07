"""Part 148 of the unit suite: the local and Tailscale transports keep a bare CR.

Owner report (2026-11-06): a command typed into a Paper server on the panel's own host showed in
the console as "> s", "> st", "> sta" ... one line per letter. Paper's JLine console rewrites its
input line with a CR after each keystroke, all on ONE line of the log; terminal.render applies those
CRs as overwrites. The local and Tailscale transports turned each bare CR into a line break before
that could happen. The paramiko transport never did, which is why only the panel host showed it.
"""
import subprocess as _sp148
import types

from unit.part01 import check
from panel.ops.ssh_manager import _core as _smc148
from panel.routes import server_files as _sf148
import app as _app148

# Exactly the bytes the live server's console log held for a typed `/pl` (escapes trimmed).
_TYPED148 = "\x1b[K> /\r\x1b[K> /p\r\x1b[K> /pl\r\r\n[23:59:01 INFO]: Bukkit Plugins:\r\nend"
_SH148 = "printf '%s' " + _smc148._quote(_TYPED148)

_out148, _err148, _rc148 = _smc148._exec_local_shell(_SH148, timeout=10)
check("local transport: a bare CR is kept, CRLF becomes LF",
      _rc148 == 0 and _out148 == _TYPED148.replace("\r\n", "\n").strip(), repr((_out148, _rc148)))

# The caller: what the console poller makes of that read is ONE command line, not one per letter.
_sf148._console_partial.pop(-148, None)
_whole148 = _sf148._console_whole_lines(-148, "B" + _out148 + "\nE")
_shown148 = [ln for ln in _app148._clean_console_text(_whole148).split("\n")]
_sf148._console_partial.pop(-148, None)
check("console: a command typed on the panel host's own server is one line, not one per letter",
      _shown148 == ["> /pl", "[23:59:01 INFO]: Bukkit Plugins:", "end"], repr(_shown148))

# Tailscale: the same decode, over a stand-in `ssh` that prints the same bytes.
_real_sub148, _real_ts148 = _smc148.subprocess, _smc148._resolve_ts_host
try:
    _smc148.subprocess = types.SimpleNamespace(
        PIPE=_sp148.PIPE, DEVNULL=_sp148.DEVNULL,
        Popen=lambda _argv, **kw: _sp148.Popen(["/bin/bash", "-c", _SH148], **kw))
    _smc148._resolve_ts_host = lambda _server: "ts148.example.test"
    _ts_out148, _ts_err148, _ts_rc148 = _smc148._run_via_ssh_cli(
        types.SimpleNamespace(sudo_enabled=False, username="u148", host="ts148.example.test",
                              port=22), "true", timeout=10)
finally:
    _smc148.subprocess, _smc148._resolve_ts_host = _real_sub148, _real_ts148
check("tailscale transport: a bare CR is kept, CRLF becomes LF",
      _ts_rc148 == 0 and _ts_out148 == _TYPED148.replace("\r\n", "\n").strip(),
      repr((_ts_out148, _ts_err148, _ts_rc148)))
