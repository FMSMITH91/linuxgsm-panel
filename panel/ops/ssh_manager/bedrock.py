"""Minecraft Bedrock's player count, read from the server's own console log.

Bedrock Dedicated Server 1.26 on NetherNet (WebRTC: TCP signalling on server-port, UDP per player)
answers no RakNet unconnected ping, and that ping is the only query gamedig's `mbe` type sends. On
the test host (BDS 1.26.63.1) nothing listens on UDP 19132 at all and `gamedig --type mbe` printed
{"error":"Failed all 2 attempts"}, so every Bedrock server's players read "unknown": the
dashboard, the bots, the backup and restart guards, "wait until empty" and the hourly
restart-when-empty check. LinuxGSM itself gives mcbserver querymode="5" (a TCP connect, no count).

The server writes every join and leave to its console, which LinuxGSM keeps in
log/console/<selfname>-console.log (tmux pipe-pane) and starts afresh on every `start` (it moves
the old one aside, command_start.sh). Each line carries BDS's own prefix:

    [2025-03-01 08:49:08:469 INFO] Player connected: Name, xuid: 2535412345678901
    [2025-03-01 08:52:10:002 INFO] Player disconnected: Name, xuid: 2535412345678901, pfid: ...

("Player Connected: Name, xuid: , pfid: ..." on a server without Xbox sign-in.) So the count is a
passive read: nothing is typed into the console the operator is watching. It is trusted only when
LinuxGSM's own running test sees the session AND the log holds this run's "Server started." line
(a log that was cleared, pruned by LinuxGSM's log cleanup or written with console logging off has
none, and a stale log would otherwise read as nobody on). A connect line that cannot be read makes
the whole count unread rather than one lower. Per player name the tally never drops below zero, so
a leave with no join before it cannot cancel someone else's join.

The tally runs on the host, in one awk pass over at most 256 bytes of each line that grep kept, so
what crosses the network is one short line whatever the log's size. It is ONE shell fragment,
used both by the panel's own reads and inside the hourly restart-when-empty cron line, so the two
cannot count differently.

The server is asked first, though (LAN discovery, below): its own answer is the count, without a
`sudo` to the account or a read of its log. The log is read only when that query gets no answer.
"""
import hashlib
import hmac
import re
import secrets
import struct

from cryptography.hazmat.primitives import padding as _padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from panel.ops.ssh_manager import _core  # noqa: E402,F401  (module object: resolves at CALL time)

BEDROCK_GAME = "mcb"
# LinuxGSM's script name for Bedrock: GameServer.lgsm_name is always "<game_type>server".
BEDROCK_SELFNAME = "mcbserver"

# The tally. POSIX awk only (Ubuntu's awk is mawk): no interval expressions, no gawk extensions, no
# `%` (cron reads one as a newline) and no single quote (it is single-quoted in the shell). Prints
# "OK <n>" for a counted run, "N" when this run's start line is missing, "B" when a join line could
# not be read. Lines are cut to 256 bytes before grep, so no line is ever held whole.
BEDROCK_TALLY_AWK = (
    '{sub(/\\r+$/,"");sub(/^NO LOG FILE! - /,"");if(!sub(/^\\[[^]]* INFO\\] /,""))next;d=0}'
    '/^Server started\\.$/{s=1;split("",n);next}'
    '/^Player [Cc]onnected: /{d=1}'
    '/^Player [Dd]isconnected: /{d=-1}'
    'd{r=substr($0,index($0,"onnected: ")+10);j=index(r,", xuid:");'
    'if(j<2||j>81){if(d>0)b=1;next}k=substr(r,1,j-1);if(d>0)n[k]++;else if(n[k]>0)n[k]--}'
    'END{for(k in n)c+=n[k];print(b?"B":s?"OK "c+0:"N")}'
)

# The longest command Debian and Ubuntu's cron runs whole: entry.c reads it into MAX_COMMAND (1000)
# bytes and drops the rest without a word, leaving a shell syntax error that never restarts.
CRON_COMMAND_MAX = 999

# What the panel's own read prints before the tally, so a reply that did not run to it (a dropped
# connection, a refused account) is told from a tally.
_MARK = "mcbp:"
_TALLY_LINE = re.compile(r"mcbp:(?:OK ([0-9]{1,6})|(D)|(N)|(B))\Z")
_FAILED = ("failed", None, None, None, None)
_PROPS_LINE = re.compile(r"(max-players|server-name|level-name)=([^\r\n]{0,120})\r?\Z")


def is_bedrock(game_type):
    """Whether a server of `game_type` is counted from its console log (LinuxGSM's mcbserver)."""
    return (game_type or "").lower() == BEDROCK_GAME


def bedrock_count_sh(selfname):
    """Shell, run AS the game account in its home, that prints the tally (see BEDROCK_TALLY_AWK) or D.

    D: LinuxGSM's own running test (check_status.sh: a session named for the script on its
    `<selfname>-<uid>` socket, or the bare one of releases before the uid file) sees no server.
    `selfname` must already have passed game_idents_ok: it is a plain word, written unquoted.
    """
    uid = "lgsm/data/%s.uid" % selfname
    return (f"export LC_ALL=C;s={selfname};[ -f {uid} ]&&s={selfname}-$(head -c 40 {uid});"
            f"TERM=screen tmux -L \"$s\" ls -F '#{{session_name}}' 2>/dev/null|grep -Fqx {selfname}"
            "||{ echo D;exit;};"
            f"timeout 20 cut -b 1-256 -- log/console/{selfname}-console.log 2>/dev/null"
            f"|grep -aE 'INFO\\] (Player|Server started)'|awk {_core._quote(BEDROCK_TALLY_AWK)}")


def bedrock_restart_check(game_type, user, selfname):
    """The hourly restart-when-empty check for a Minecraft Bedrock server, or None.

    None for any other game, and for a line too long for cron (an account name past the 32
    characters useradd allows): _core.daily_restart_check_cmd then writes its gamedig query, which
    a RakNet server still answers. Cron runs the line in the account's home; only a counted "OK 0"
    restarts, and D (no session), N (no start line), B (an unreadable join) or nothing at all wait
    for the next hour. Head and tail are _core.daily_restart_check_cmd's, which the cron upgrade's
    table (cron._restart_check_res) reads back. Names must already have passed game_idents_ok.
    """
    if not is_bedrock(game_type):
        return None
    flag = f"/home/{user}/.restart-pending"
    line = (f"[ -f {flag} ] && {{ P=$({bedrock_count_sh(selfname)}); if [ \"$P\" = \"OK 0\" ]; then "
            f"/home/{user}/{selfname} restart >/dev/null 2>&1; rm -f {flag}; fi; }}")
    return line if len(line) <= CRON_COMMAND_MAX else None


def bedrock_read_sh(user, selfname):
    """The panel's read: the tally line, then server.properties' capacity, name and level."""
    return (f"cd /home/{user} || exit 3; P=$({bedrock_count_sh(selfname)}); echo \"{_MARK}$P\"; "
            "grep -aE '^(max-players|server-name|level-name)=' serverfiles/server.properties "
            "2>/dev/null | head -n 6 | cut -b 1-160")


def _props(lines):
    """{key: value} from server.properties lines (the first of each key), values whitespace-collapsed."""
    got = {}
    for ln in lines:
        m = _PROPS_LINE.match(ln.strip(" \t"))
        if m and m.group(1) not in got:
            got[m.group(1)] = " ".join(m.group(2).split())
    return got


def _capacity(text):
    """The max-players value as an int, or None when it is not a plain number."""
    return int(text) if text and text.isdecimal() and len(text) <= 6 else None


def _state(line):
    """The tally line as (state, count): ok/down/unread, or (None, None) when it is not one."""
    m = _TALLY_LINE.match(line)
    if not m:
        return None, None
    if m.group(1) is not None:
        return "ok", int(m.group(1))
    return ("down" if m.group(2) else "unread"), None


# ── Asking the server: NetherNet LAN discovery ──────────────────────────────────────────────────
# A NetherNet Bedrock server answers LAN discovery on UDP 7551 (enable-lan-visibility, on by
# default): a request packet in, a response packet out, carrying the world card the game's LAN list
# shows: server name, level name, player count and capacity. Layout (as reverse-engineered by the
# NetherNet spec and implementations, and measured against BDS 1.26.63 with this module's codec):
#
#   datagram  = HMAC-SHA256(key, payload) (32 bytes) + AES-256-ECB(key, PKCS#7(payload))
#   key       = SHA-256 of the application id 0xdeadbeef as a little-endian uint64
#   payload   = uint16 length of the whole payload | uint16 packet id (0 request, 1 response) |
#               uint64 sender id | 8 bytes padding | packet body          (all little-endian)
#   response body = uint32 length | that many ASCII hex digits of the ServerData below
#   ServerData v7 = uint8 7 | string server name | varint protocol | string game version |
#                   string level name | varint players | varint max players | varint game type |
#                   bool editor | bool hardcore | bool online auth | bool self-signed auth |
#                   string nonce | varint connection type
#   (string = varuint32 byte length + UTF-8; varint = zigzag varuint32, at most 5 bytes)
#
# The key is a fixed public constant: the cipher hides nothing, it is only the wire format, and
# nothing secret is sent or kept. The reply is checked strictly all the same (HMAC, padding, every
# length, the ServerData version, no byte left over), since the bytes come from a UDP socket.
#
# The host only exchanges the datagram: python3 (a LinuxGSM dependency), standard library only,
# run as the login (no sudo), prints the reply's hex. Decrypting and parsing happen here, with
# the panel's own cryptography package. Before sending, it requires that every socket bound to
# UDP 7551 belongs to the server's account (/proc/net/udp's uid column, readable by anyone): only
# one process on a host can answer 7551, and a second Bedrock server in another account, or one
# the panel does not manage, must not lend its count to this one.
LAN_PORT = 7551
_LAN_KEY = hashlib.sha256(struct.pack("<Q", 0xDEADBEEF)).digest()
_LAN_REPLY_MAX = 2048          # bytes the host reads from the socket; BDS 1.26.63 sent 176
_LAN_SERVER_DATA_VERSION = 7
_LAN_TEXT_MAX = 256            # longest string field read from a reply
_LAN_COUNT_MAX = 999999        # as _capacity: at most six digits
_QMARK = "mcbq:"
_LAN_REPLY_RE = re.compile(r"(?:[0-9a-f]{2}){48,%d}\Z" % _LAN_REPLY_MAX)
_LAN_HEX_TEXT_RE = re.compile(rb"[0-9a-fA-F]*\Z")
_LAN_QUERY_PY = (
    "import pwd,socket,sys\n"
    "u=str(pwd.getpwnam(sys.argv[1]).pw_uid)\n"
    "o=set()\n"
    "for f in ('/proc/net/udp','/proc/net/udp6'):\n"
    " try:\n"
    "  with open(f) as h:\n"
    "   for n,l in enumerate(h):\n"
    "    if n>65536:sys.exit(3)\n"
    "    w=l.split()\n"
    "    if len(w)>7 and w[1].endswith(':%04X'):o.add(w[7])\n"
    " except OSError:pass\n"
    "if o!={u}:sys.exit(3)\n"
    "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
    "s.settimeout(2)\n"
    "s.connect(('127.0.0.1',%d))\n"
    "s.send(bytes.fromhex(sys.argv[2]))\n"
    "print(s.recv(%d).hex())\n"
) % (LAN_PORT, LAN_PORT, _LAN_REPLY_MAX)


def _lan_cipher():
    """The discovery packets' AES-256-ECB cipher: the protocol's own, with its fixed public key."""
    # nosemgrep: python.cryptography.security.insecure-cipher-mode-ecb.insecure-cipher-mode-ecb
    return Cipher(algorithms.AES(_LAN_KEY), modes.ECB())  # nosec B305 # NOSONAR - wire format, public key, no secret


def lan_packet(payload):
    """One discovery datagram for `payload` (length prefix included): the HMAC, then the ciphertext."""
    padder = _padding.PKCS7(128).padder()
    enc = _lan_cipher().encryptor()
    body = enc.update(padder.update(payload) + padder.finalize()) + enc.finalize()
    return hmac.new(_LAN_KEY, payload, hashlib.sha256).digest() + body


def lan_request(sender_id):
    """The discovery request (packet id 0, no body) from `sender_id`, as the datagram's bytes."""
    body = struct.pack("<HQ8x", 0, sender_id)
    return lan_packet(struct.pack("<H", len(body) + 2) + body)


_LAN_REQUEST_HEX = lan_request(secrets.randbits(64)).hex()


def _lan_payload(raw):
    """The decrypted payload of datagram `raw`, its HMAC and padding checked. Raises ValueError."""
    if len(raw) < 48 or (len(raw) - 32) % 16:
        raise ValueError("not a discovery datagram")
    dec = _lan_cipher().decryptor()
    unpadder = _padding.PKCS7(128).unpadder()
    payload = unpadder.update(dec.update(raw[32:]) + dec.finalize()) + unpadder.finalize()
    if not hmac.compare_digest(hmac.new(_LAN_KEY, payload, hashlib.sha256).digest(), raw[:32]):
        raise ValueError("checksum mismatch")
    return payload


def _lan_server_data(payload):
    """The ServerData bytes of a response payload. Raises ValueError for anything else."""
    if len(payload) < 24:
        raise ValueError("short payload")
    length, packet_id = struct.unpack_from("<HH", payload)
    (text_len,) = struct.unpack_from("<I", payload, 20)
    text = payload[24:]
    if length != len(payload) or packet_id != 1 or text_len != len(text) or text_len % 2:
        raise ValueError("not a discovery response")
    if not _LAN_HEX_TEXT_RE.match(text):
        raise ValueError("server data is not hex")
    return bytes.fromhex(text.decode("ascii"))


class _LanReader:
    """Reads ServerData's fields in order; any field that runs past the end raises ValueError."""

    def __init__(self, data):
        self.data, self.pos = data, 0

    def byte(self):
        if self.pos >= len(self.data):
            raise ValueError("truncated")
        self.pos += 1
        return self.data[self.pos - 1]

    def flag(self):
        b = self.byte()
        if b > 1:
            raise ValueError("not a bool")
        return b

    def varuint(self):
        val = 0
        for shift in range(0, 35, 7):
            b = self.byte()
            val |= (b & 0x7F) << shift
            if not b & 0x80:
                return val
        raise ValueError("varint longer than 5 bytes")

    def varint(self):
        u = self.varuint()
        return (u >> 1) ^ -(u & 1)

    def text(self):
        n = self.varuint()
        if n > _LAN_TEXT_MAX or self.pos + n > len(self.data):
            raise ValueError("bad string length")
        self.pos += n
        return self.data[self.pos - n:self.pos].decode("utf-8")


def _lan_name(text):
    """A name from the reply as the page may show it: controls and blanks to one space, at most 120."""
    clean = " ".join("".join(c if c.isprintable() else " " for c in text).split())
    return clean[:120] or None


def _lan_fields(data):
    """(players, max, server name, level name) from ServerData v7. Raises ValueError."""
    r = _LanReader(data)
    if r.byte() != _LAN_SERVER_DATA_VERSION:
        raise ValueError("unknown server data version")
    name = r.text()
    r.varint()                                  # protocol
    r.text()                                    # game version
    level = r.text()
    players, cap = r.varint(), r.varint()
    r.varint()                                  # game type
    for _ in range(4):                          # editor, hardcore, online auth, self-signed auth
        r.flag()
    r.text()                                    # nonce: read past, never kept
    r.varint()                                  # connection type
    if r.pos != len(data) or not (0 <= players <= _LAN_COUNT_MAX and 0 <= cap <= _LAN_COUNT_MAX):
        raise ValueError("server data out of range")
    return players, cap, _lan_name(name), _lan_name(level)


def lan_reply(hex_text):
    """(players, max, name, level) from the host's hex of a discovery reply, or None for any other bytes."""
    if not _LAN_REPLY_RE.match(hex_text or ""):
        return None
    try:
        return _lan_fields(_lan_server_data(_lan_payload(bytes.fromhex(hex_text))))
    except (ValueError, struct.error, UnicodeDecodeError):
        return None


def bedrock_query_sh(user):
    """Shell, run as the login on the server's host, that prints `mcbq:<reply hex>` or fails.

    It fails (prints nothing, exits non-zero) when no socket on UDP 7551 is the account's, when a
    socket on it is another account's, or when no reply came within two seconds. `user` must
    already have passed game_idents_ok.
    """
    return (f"R=$(timeout 5 python3 -I -c {_core._quote(_LAN_QUERY_PY)} {_core._quote(user)} "
            f"{_LAN_REQUEST_HEX} 2>/dev/null)&&[ -n \"$R\" ]&&echo \"{_QMARK}$R\"")


def bedrock_slots_cmd(user, selfname):
    """The one command bedrock_slots sends: the query, then, only if it failed, the log read as the account.

    Raises UnsafeGameAccount for a name game_user_cmd refuses.
    """
    read = _core.game_user_cmd(user, bedrock_read_sh(user, selfname), selfname=selfname)
    return f"{bedrock_query_sh(user)}||{read}"


def bedrock_slots(server, user, selfname=None):
    """A Bedrock server's (state, count, max, name, level), from ONE command on its host.

    The server itself is asked first (bedrock_query_sh: no sudo, no log read); only when it does
    not answer does the same command go on to read the console log as the account
    (bedrock_read_sh). A reply that came but cannot be read costs one more command: the log read.

    state is "ok" (the server's own count, or the int the log adds up to), "down" (LinuxGSM's
    running test sees no server: no count), "unread" (no start line in the log, or a join line it
    could not read: the caller may still try gamedig, which answers on a RakNet server) or "failed"
    (refused account, transport error, or a reply without the tally: unknown). max, name and level
    come from the server's reply, or from server.properties when the log was read, else None.
    Never raises.
    """
    selfname = selfname or BEDROCK_SELFNAME
    if not _core.game_idents_ok(user, selfname):
        return _FAILED
    try:
        out, _, _ = _core.run_command(server, bedrock_slots_cmd(user, selfname), timeout=30, sudo=False)
    except Exception:
        return _FAILED
    lan = [ln.strip() for ln in (out or "").splitlines() if ln.strip().startswith(_QMARK)]
    if not lan:
        return _reply(out)
    got = lan_reply(lan[0][len(_QMARK):]) if len(lan) == 1 else None
    return ("ok",) + got if got else _log_slots(server, user, selfname)


def _log_slots(server, user, selfname):
    """The console-log read alone, as the account: for a discovery reply that could not be read."""
    try:
        out, _, _ = _core.shell_as_game_user(server, user, bedrock_read_sh(user, selfname),
                                             timeout=30, selfname=selfname)
    except Exception:
        return _FAILED
    return _reply(out)


def _reply(out):
    """The answer bedrock_slots gives for the read's output: one tally line, then server.properties."""
    lines = (out or "").splitlines()
    tally = [ln.strip() for ln in lines if ln.strip().startswith(_MARK)]
    state, count = _state(tally[0]) if len(tally) == 1 else (None, None)
    if state is None:
        return _FAILED
    props = _props(ln for ln in lines if not ln.strip().startswith(_MARK))
    return (state, count, _capacity(props.get("max-players")),
            props.get("server-name") or None, props.get("level-name"))
