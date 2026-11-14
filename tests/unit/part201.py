"""Part 201 of the unit suite: Minecraft Bedrock's player count, asked of the server itself (LAN discovery).

Held here:
* The reply codec (bedrock.lan_reply) over the bytes a real BDS 1.26.63 sent to a discovery request
  on UDP 7551, and over replies built by the same codec: the count, capacity, server name and level
  name come out; any byte that is not a well-formed reply (checksum, padding, every length, the
  packet id, the ServerData version, a field past the end, a byte left over, an oversize reply,
  hex that is not hex) reads as no reply, never as a count.
* The host side: the python3 the query runs, executed here against a loopback UDP stand-in and a
  stand-in /proc/net/udp: it sends the request, prints the reply's hex, and refuses (exit 3, sends
  nothing) when no socket on the port is the account's or one of them is another account's.
* The shell around it: the query's reply is printed with its mark; a failed or silent query goes
  on to the log read, and only then.
* bedrock_slots and its callers: one command, the server's answer first, the console log only when
  the server did not answer, and a reply that cannot be read costs the log read and no more;
  player_count and player_slots take the server's answer without a gamedig query; the status poll
  caches it.

HOW IT RUNS. The codec runs in-process. The host's python3 and the shell run under this machine's
python3 and sh with a loopback UDP socket bound to a free port (the script's port and /proc paths
rewritten to it): nothing leaves the machine. Everything else drives part12's app with its
transport tripwire armed and every host call stubbed. Nothing reaches a host or data/.
"""
import hashlib as _hl201
import os as _os201
import shutil as _shutil201
import socket as _sock201
import struct as _st201
import subprocess as _sp201  # nosec B404 - the query's own python3 and shell, run here
import sys as _sys201
import tempfile as _tf201
import threading as _th201

from unit.part01 import check, eq
from unit.part12 import (P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_delete_server, _p9_new_server, _p9_patch,
                         _p9_patch_sm, _p9_restore_all)
from panel.core import panel_state as _ps201
from panel.ops.ssh_manager import _core as _core201, bedrock as _bd201, cron as _cron201
from panel.services import monitoring as _mon201

_trips201 = len(_P9_TRIPPED)

# ── 1. the reply codec ──────────────────────────────────────────────────────────────────────────
# What BDS 1.26.63.1 (server-name LinuxGSM, level-name "Bedrock level", max-players 10, nobody on)
# sent back to one discovery request on 127.0.0.1:7551, as the host's python3 printed it.
_REAL201 = (
    "0efbc72a7539e94106427f172b723532db8b2fe5988a42035a3e3e913dfb5f9cf016c4ba0d015425966fe2a4b000b5bb7b"
    "c2d1f237e3d247e052b1a9ca02a0cf62cac597b9196f8027ca3d089a6a8f2c7a49b8df9f45006b8ffa9f280d4f59dec9e2"
    "c33f916499b9a6fb79bc2f09a72a59a5d5ac25f1a7a18283a6384e496258769d7ecf40c561792f91611bb4f9836dd0567f"
    "e079286ea4fd101ab6403d5cb4a4acc4ac4aa0e09be2cc9972bcf1a470")


def _vu201(n):
    out = bytearray()
    while n >= 0x80:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    return bytes(out + bytes([n]))


def _vi201(n):
    return _vu201(((n << 1) ^ (n >> 31)) & 0xFFFFFFFF)


def _s201(text):
    raw = text.encode("utf-8") if isinstance(text, str) else text
    return _vu201(len(raw)) + raw


def _data201(players=3, cap=10, name="My Bedrock", level="Bedrock level", version=7, tail=b"",
             flags=b"\x00\x00\x01\x00"):
    """The ServerData v7 bytes as BDS writes them, in the NetherNet field order."""
    return (bytes([version]) + _s201(name) + _vi201(2225) + _s201("1.26.63") + _s201(level)
            + _vi201(players) + _vi201(cap) + _vi201(0) + flags + _s201("00112233aabbccdd") + _vi201(4) + tail)


def _reply201(data=None, packet_id=1, length_delta=0, text_delta=0, text=None):
    """A discovery response datagram's hex carrying `data`, built by the module's own packet codec."""
    text = (data if data is not None else _data201()).hex().encode() if text is None else text
    body = _st201.pack("<HQ8xI", packet_id, 0x1122334455667788, len(text) + text_delta) + text
    return _bd201.lan_packet(_st201.pack("<H", len(body) + 2 + length_delta) + body).hex()


eq("bedrock query: the reply a real BDS 1.26.63 sent decodes to its count, capacity, server name and level",
   _bd201.lan_reply(_REAL201), (0, 10, "LinuxGSM", "Bedrock level"))
eq("bedrock query: a reply with players on carries their count",
   _bd201.lan_reply(_reply201(_data201(players=7, cap=20))), (7, 20, "My Bedrock", "Bedrock level"))
eq("bedrock query: names are shown with control characters and blanks as one space, at most 120 characters",
   _bd201.lan_reply(_reply201(_data201(name="A\x1b[2J  B\tC\x00", level="L" * 200)))[2:], ("A [2J B C", "L" * 120))


def _flip201(hexs, at):
    raw = bytearray(bytes.fromhex(hexs))
    raw[at] ^= 1
    return raw.hex()


_bad201 = {
    "a checksum byte changed": _flip201(_REAL201, 3),
    "a ciphertext byte changed": _flip201(_REAL201, 60),
    "the last block dropped": _REAL201[:-32],
    "only the checksum": _REAL201[:64],
    "a request, not a response": _reply201(packet_id=0),
    "a declared length one short": _reply201(length_delta=-1),
    "a hex length one long": _reply201(text_delta=1),
    "an odd hex length": _reply201(text=b"07a"),
    "hex text that is not hex": _reply201(text=_data201().hex().encode()[:-2] + b"zz"),
    "hex text with blanks (fromhex would take them)": _reply201(text=b" " + _data201().hex().encode() + b" "),
    "an unknown ServerData version": _reply201(_data201(version=8)),
    "a byte left over": _reply201(_data201(tail=b"\x00")),
    "a field past the end": _reply201(_data201()[:-3]),
    "a bool that is not 0 or 1": _reply201(_data201(flags=b"\x00\x02\x01\x00")),
    "a negative player count": _reply201(_data201(players=-1)),
    "a count past six digits": _reply201(_data201(players=1000000)),
    "a name longer than a reply allows": _reply201(_data201(name="n" * 257)),
    "a name that is not UTF-8": _reply201(_data201(name=b"\xff\xfe")),
    "a varint longer than five bytes": _reply201(_data201()[:1] + b"\x80" * 6 + b"\x00"),
    "an uppercase outer hex": _REAL201.upper(),
    "more than the host reads": _REAL201 + "00" * 2048,
    "nothing": "",
}
eq("bedrock query: a reply that is not well-formed is no reply, never a count (each case)",
   {k: _bd201.lan_reply(v) for k, v in _bad201.items()}, {k: None for k in _bad201})
check("bedrock query: the reply checks hold the strict reads (a hostile reply of the right size is no count)",
      _bd201.lan_reply(_flip201(_REAL201, 175)) is None and _bd201.lan_reply(None) is None, "")
_req201 = _bd201._lan_payload(bytes.fromhex(_bd201._LAN_REQUEST_HEX))
check("bedrock query: the request is a discovery request (length 20, packet id 0) the codec's own check reads",
      len(_req201) == 20 and _st201.unpack_from("<HH", _req201) == (20, 0), _req201.hex())
check("bedrock query: the key is SHA-256 of the application id 0xdeadbeef as a little-endian uint64",
      _bd201._LAN_KEY == _hl201.sha256(bytes.fromhex("efbeadde00000000")).digest(), "")

# ── 2. the host side: python3 over a loopback stand-in ──────────────────────────────────────────


def _host201(owner_uids, answer=True, user=None):
    """(rc, stdout, datagrams received) from the host's python3, its port and /proc rewritten to a stand-in."""
    tmp = _tf201.mkdtemp(prefix="p201-")
    srv = _sock201.socket(_sock201.AF_INET, _sock201.SOCK_DGRAM)
    got = []
    try:
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        with open(_os201.path.join(tmp, "udp"), "w", encoding="utf-8") as fh:
            fh.write("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
            for i, uid in enumerate(owner_uids):
                fh.write("  %d: 00000000:%04X 00000000:0000 07 00000000:00000000 00:00000000 00000000  %5d        0 %d\n"
                         % (i, port, uid, 9000 + i))
            fh.write("  9: 00000000:0050 00000000:0000 07 00000000:00000000 00:00000000 00000000 4242        0 1\n")
        here = (":%04X'" % _bd201.LAN_PORT, "'127.0.0.1',%d" % _bd201.LAN_PORT, "/proc/net/udp")
        if not all(h in _bd201._LAN_QUERY_PY for h in here):
            return "the script no longer names its port and /proc path as this stand-in rewrites them", "", []
        py = (_bd201._LAN_QUERY_PY.replace(":%04X'" % _bd201.LAN_PORT, ":%04X'" % port)
              .replace("'127.0.0.1',%d" % _bd201.LAN_PORT, "'127.0.0.1',%d" % port)
              .replace("/proc/net/udp", _os201.path.join(tmp, "udp")))

        def _serve():
            srv.settimeout(5)
            try:
                data, addr = srv.recvfrom(4096)
                if data:           # b"" is this function's own wake-up after a refusal
                    got.append(data)
                if data and answer:
                    srv.sendto(bytes.fromhex(_REAL201), addr)
            except OSError:
                pass
        th = _th201.Thread(target=_serve, daemon=True)
        th.start()
        name = user or __import__("pwd").getpwuid(_os201.getuid()).pw_name
        res = _sp201.run([_sys201.executable, "-I", "-c", py, name, _bd201._LAN_REQUEST_HEX],  # nosec B603
                         capture_output=True, text=True, timeout=30, check=False)
        if not got:
            with _sock201.socket(_sock201.AF_INET, _sock201.SOCK_DGRAM) as wake:
                wake.sendto(b"", ("127.0.0.1", port))
        th.join(6)
        return res.returncode, res.stdout.strip(), got
    finally:
        srv.close()
        _shutil201.rmtree(tmp, ignore_errors=True)


_me201 = _os201.getuid()
_h_ok201 = _host201([_me201, _me201])
check("bedrock query host: the account's own socket on the port is asked once, and the reply's hex is printed",
      _h_ok201[0] == 0 and _h_ok201[1] == _REAL201 and _h_ok201[2] == [bytes.fromhex(_bd201._LAN_REQUEST_HEX)],
      repr(_h_ok201)[:300])
_h_other201 = _host201([_me201 + 1])
_h_mixed201 = _host201([_me201, _me201 + 1])
_h_none201 = _host201([])
check("bedrock query host: a port held by another account, by two accounts, or by nobody sends nothing (exit 3)",
      [r[:3] for r in (_h_other201, _h_mixed201, _h_none201)] == [(3, "", [])] * 3,
      repr((_h_other201, _h_mixed201, _h_none201))[:300])
_h_quiet201 = _host201([_me201], answer=False)
check("bedrock query host: a server that does not answer prints nothing and fails",
      _h_quiet201[0] != 0 and _h_quiet201[1] == "" and len(_h_quiet201[2]) == 1, repr(_h_quiet201)[:300])

# ── 3. the shell around it ──────────────────────────────────────────────────────────────────────


def _sh201(stub_body):
    """What the query's shell, then `||echo READ`, prints with a stand-in python3 running `stub_body`."""
    tmp = _tf201.mkdtemp(prefix="p201s-")
    try:
        _os201.makedirs(_os201.path.join(tmp, "bin"))
        stub = _os201.path.join(tmp, "bin", "python3")
        with open(stub, "w", encoding="utf-8") as fh:
            fh.write("#!/bin/sh\n" + stub_body + "\n")
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- owner-only, a temp stand-in
        _os201.chmod(stub, 0o700)  # nosec B103
        env = dict(_os201.environ, PATH=_os201.path.join(tmp, "bin") + ":" + _os201.environ.get("PATH", "/usr/bin:/bin"))
        res = _sp201.run(["sh", "-c", _bd201.bedrock_query_sh("p201mcb") + "||echo READ"], env=env,  # nosec B603 B607
                         capture_output=True, text=True, timeout=30, check=False)
        return res.stdout.strip()
    finally:
        _shutil201.rmtree(tmp, ignore_errors=True)


eq("bedrock query shell: a reply is printed with its mark and the log is not read; a refusal, a silent "
   "query or no python3 output goes on to the log read",
   [_sh201("echo abcd"), _sh201("exit 3"), _sh201("exit 0"), _sh201("echo; exit 0")],
   ["mcbq:abcd", "READ", "READ", "READ"])

# ── 4. bedrock_slots and its callers ────────────────────────────────────────────────────────────


def _slots201(reply, log="mcbp:OK 5\nmax-players=12\n"):
    """bedrock_slots' answer, [commands run on the host], [log-only reads as the account]."""
    runs, reads = [], []

    def _run(server, cmd, **k):
        runs.append((cmd, k.get("sudo")))
        return reply, "", 0

    def _shell(server, user, sh, **k):
        reads.append(sh)
        return log, "", 0
    try:
        _p9_patch_sm("run_command", _run)
        _p9_patch_sm("shell_as_game_user", _shell)
        return _bd201.bedrock_slots(None, "p201mcb"), runs, reads
    finally:
        _p9_restore_all()


_sl_ok201 = _slots201("mcbq:" + _reply201(_data201(players=4, cap=16)) + "\n")
check("bedrock slots: the server's own answer, from ONE command run as the login (no sudo), and no log read",
      _sl_ok201 == (("ok", 4, 16, "My Bedrock", "Bedrock level"),
                    [(_bd201.bedrock_slots_cmd("p201mcb", "mcbserver"), False)], []), repr(_sl_ok201)[:300])
check("bedrock slots: that command asks the server first and reads the log only when it failed",
      _bd201.bedrock_slots_cmd("p201mcb", "mcbserver").startswith(_bd201.bedrock_query_sh("p201mcb") + "||sudo -u p201mcb ")
      and _bd201.bedrock_slots_cmd("p201mcb", "mcbserver").endswith(
          _core201._quote(_core201.GAME_SHELL_CWD + _bd201.bedrock_read_sh("p201mcb", "mcbserver"))), "")
_sl_log201 = _slots201("mcbp:OK 2\nmax-players=10\n")
check("bedrock slots: a server that did not answer is counted from the log the same command read",
      _sl_log201[0] == ("ok", 2, 10, None, None) and len(_sl_log201[1]) == 1 and _sl_log201[2] == [],
      repr(_sl_log201)[:300])
_sl_bad201 = _slots201("mcbq:" + _flip201(_REAL201, 3) + "\n")
_sl_two201 = _slots201("mcbq:%s\nmcbq:%s\n" % (_REAL201, _REAL201))
check("bedrock slots: a reply that cannot be read, or two of them, costs one log read as the account, no more",
      _sl_bad201[0] == ("ok", 5, 12, None, None) and len(_sl_bad201[1]) == 1
      and _sl_bad201[2] == [_bd201.bedrock_read_sh("p201mcb", "mcbserver")]
      and _sl_two201[0] == ("ok", 5, 12, None, None) and len(_sl_two201[2]) == 1, repr((_sl_bad201, _sl_two201))[:300])


def _pc201(fn):
    """cron.<fn> for a Bedrock server whose host answers the query, and [commands sent]."""
    sent = []

    def _run(server, cmd, **k):
        sent.append(cmd)
        return ("mcbq:" + _reply201(_data201(players=6, cap=30, level="Lush Caves")) if "mcbq:" in cmd else ""), "", 0
    try:
        _p9_patch_sm("run_command", _run)
        _p9_patch_sm("shell_as_game_user", lambda *a, **k: sent.append(a[2]) or ("", "", 1))
        _p9_patch_sm("_gamedig_host", lambda server: "192.0.2.21")
        srv = type("Srv", (), {"id": 920101})()
        return getattr(_cron201, fn)(srv, "p201mcb", "mcb", 19132, None), sent
    finally:
        _p9_restore_all()


_pc_cnt201 = _pc201("player_count")
_cron201._game_map_cache.pop((920101, 19132), None)
_pc_sl201 = _pc201("player_slots")
_map201 = _cron201._cached_map((920101, 19132))
_cron201._game_map_cache.pop((920101, 19132), None)
check("player count (mcb): the server's answer, one command, no gamedig query and no log read",
      _pc_cnt201[0] == 6 and len(_pc_cnt201[1]) == 1 and "gamedig" not in _pc_cnt201[1][0], repr(_pc_cnt201)[:300])
check("player slots (mcb): count, capacity and name from the server's answer, and its level fills the map cache",
      _pc_sl201[0] == (6, 30, "My Bedrock") and len(_pc_sl201[1]) == 1 and _map201 == "Lush Caves",
      repr((_pc_sl201, _map201))[:300])

_sid201 = _p9_new_server(P9_HOST, "p201mcb", "mcb", 19132, name="p201-mcb", status="online")
_poll201 = {"runs": 0, "reads": 0}


def _poll_run201(server, cmd, **k):
    if "mcbq:" in cmd:
        _poll201["runs"] += 1
        return "mcbq:" + _reply201(_data201(players=2, cap=8)), "", 0
    return "", "", 1


def _poll_shell201(server, user, sh, **k):
    _poll201["reads"] += user == "p201mcb"
    return "", "", 1


try:
    _p9_arm(who="part201")
    _p9_patch_sm("run_command", _poll_run201)
    _p9_patch_sm("shell_as_game_user", _poll_shell201)
    _p9_patch_sm("_gamedig_host", lambda server: "192.0.2.21")
    _p9_patch(_mon201, "sm_player_slots_batch", lambda remote, acct, targets: {t[0]: (None, None, None) for t in targets})
    _p9_patch(_mon201, "_batch_account", lambda remote, rows: None)
    _p9_patch(_mon201, "sm_player_count_via_lgsm_query", lambda *a, **k: None)
    _p9_patch(_mon201, "sm_get_server_status", lambda *a, **k: "online")
    _p9_patch(_mon201, "lgsm_get_values", lambda *a, **k: {})
    _mon201._batch_failed_at.pop(P9_HOST, None)
    _mon201._refresh_player_counts(_p9)
    _poll201["cache"] = dict(_ps201._player_counts.get(_sid201) or {})
finally:
    _p9_restore_all()
check("status poll (mcb): the server's answer is cached (count, capacity, name) with no read as the account",
      _poll201["cache"].get("count") == 2 and _poll201["cache"].get("max") == 8
      and _poll201["cache"].get("name") == "My Bedrock" and _poll201["runs"] == 1 and _poll201["reads"] == 0,
      repr(_poll201))
_ps201._player_counts.pop(_sid201, None)
_p9_delete_server(_sid201)
eq("bedrock query: nothing this part drove reached a real transport (part12's tripwire, armed)",
   _P9_TRIPPED[_trips201:], [])
