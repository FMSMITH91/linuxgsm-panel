"""Part 260 of the unit suite: review pass 31's security fixes.

1. install.sh _gitc: on a root run git never runs as root in a tree another account controls. The
   account comes from PANEL_DIR itself, not from a .git the panel user can rename away for an
   instant; git stops at PANEL_DIR (GIT_CEILING_DIRECTORIES), so a missing .git is never a walk up
   into the panel user's home; root runs git only in a folder it opened without following a link and
   found root's, with SUDO_UID removed (git-config(1), safe.directory: as root git also trusts the
   uid in SUDO_UID); and when the owner cannot be settled, git does not run.
2. The web server (wsgi_serve.serve, started for real on loopback in a child process) closes a
   connection that sends nothing, and one that stops part-way through its headers; keeps serving when
   idle connections have used every descriptor (EMFILE); and keeps a Socket.IO WebSocket open for
   several times its read timeout while the browser answers the heartbeat (the console and terminal).
   The unit templates set LimitNOFILE.
3. An SFTP key is a credential that signs in with no session: adding one takes the password and, with
   2FA on, a current single-use code (as the API token's mint does); adding and removing raise the
   credential_change alert and show in the account's security notices; and every path that takes an
   account back (password change, sign out everywhere, an admin's reset, deactivation) removes the
   account's keys. manage.py reset-password and deactivate are checked in tests/manage_test.py.
4. The game account's systemd user manager folders are sign-in paths: ~/.config/systemd,
   ~/.config/environment.d, ~/.config/containers (Quadlet) and ~/.local/share/systemd, and the folders
   above them, are never written, created or renamed onto by the file browser or the SFTP service (by
   name, and on the host by the resolved path), and a restore keeps the account's own and brings in
   none from the archive.
5. A ufw rule with per-rule logging (`ufw allow log 22/tcp`, `ufw limit log-all ssh`) is read for what it
   is: ufw prints " (log)" / " (log-all)" after the From column, and From read "Anywhere (log)", so a
   public rule with logging counted as public nowhere: open public SSH read "off", and Disable public
   SSH and Close port answered done with the port still open. The rows are written with ufw 0.36's own
   format (backend_iptables.get_status: "%-26s %-12s%-26s%s%s").
6. World reset's reading of a LinuxGSM config line (_wwr_assigned, through _wwr_cfg_key) takes linear
   time on a long value (it was quadratic, on a request greenlet), and still refuses every arithmetic
   context bash has: $((…)), $[…], ${a[…]}, ${a:off} and ${$:off}.
7. An encrypted panel backup is written as version 2: AES-256-GCM (OWASP Cryptographic Storage Cheat
   Sheet: authenticated, GCM first, a 256-bit key) under a key Argon2id derives from the passphrase at
   the Password Storage Cheat Sheet's first configuration (m=47104 KiB, t=1, p=1), with the header as
   associated data. A version-1 (Fernet under scrypt) backup still opens; an upload of either is taken;
   a costly header is refused before anything is derived. The passphrase needs 15 characters (OWASP
   Authentication Cheat Sheet, no MFA), and the Backups card says when a stored one is shorter.
"""
import base64 as _b64_260
import os
import pwd as _pwd260
import re as _re260
import shlex as _shlex260
import shutil as _shutil260
import socket as _socket260
import struct as _struct260
import tarfile as _tarfile260
import subprocess as _sp260  # nosec B404 - bash and git on fixture folders made here
import sys as _sys260
import tempfile as _tf260
import time as _time260

from unit import REPO_ROOT as _ROOT260
from unit.part01 import check, eq, skip
from unit.part06 import _inst, _inst_shfn
from unit.part12 import P9_ADMIN, _p9, _p9_client, _p9_patch, _p9_restore_all
from panel.core import wsgi_serve as _wsmod260
from panel.ops import socket_hooks as _sh260
# The admin edit form's "reset the password" checkbox (its field name, not a secret).
_RESET_BOX260 = "reset_password"

_TMP260 = _tf260.mkdtemp(prefix="p260-")
_ME260 = _sp260.run(["id", "-un"], capture_output=True, text=True).stdout.strip()  # nosec B603 B607 - fixed argv
_GIT_ENV260 = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                   GIT_AUTHOR_NAME="p260", GIT_AUTHOR_EMAIL="p260@example.invalid",
                   GIT_COMMITTER_NAME="p260", GIT_COMMITTER_EMAIL="p260@example.invalid")
for _k260 in ("GIT_DIR", "GIT_WORK_TREE", "GIT_CEILING_DIRECTORIES"):
    _GIT_ENV260.pop(_k260, None)


def _git260(*args):
    return _sp260.run(["git", *args], capture_output=True, text=True, env=_GIT_ENV260)  # nosec B603 B607 - fixture repo


def _give_away260(path):
    """On the CI's root lane, hand `path` (whole) to nobody, so the tree is NOT root's, as on a host."""
    if os.geteuid() != 0:
        return
    for dp, dn, fn in os.walk(path):
        for n in dn + fn:
            os.lchown(os.path.join(dp, n), 65534, 65534)
    os.lchown(path, 65534, 65534)


def _repo260(path):
    """A git repository with one commit at `path`."""
    os.makedirs(path, exist_ok=True)
    _git260("init", "-q", path)
    _git260("-C", path, "commit", "-q", "--allow-empty", "-m", "p260")


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. install.sh _gitc
# ════════════════════════════════════════════════════════════════════════════════════════════════
_GITC260 = _inst_shfn("_gitc")
# A root run as the suite can stage it without being root: `id -u` answers 0, and sudo -u is
# recorded and then runs the command as this account (the panel user here).
_FAKE_ROOT260 = ('id() { if [ "$#" -eq 1 ] && [ "$1" = -u ]; then echo 0; else command id "$@"; fi; }\n'
                 'sudo() { echo "SUDO $1 $2" >&2; [ "$1" = -u ] && shift 2; "$@"; }\n')


def _gitc260(panel_dir, cmd, panel_user=None, fake_root=True, extra="", env=None):
    """Run `_gitc <cmd>` with PANEL_DIR/PANEL_USER set; -> (rc, stdout, stderr)."""
    script = ("set -uo pipefail\nPANEL_DIR=%s\nPANEL_USER=%s\n" % (
        _shlex260.quote(panel_dir), _shlex260.quote(_ME260 if panel_user is None else panel_user))
        + (_FAKE_ROOT260 if fake_root else "") + _GITC260 + extra + "_gitc " + cmd + "\n")
    try:
        r = _sp260.run(["bash", "-c", script], capture_output=True, text=True, timeout=60,  # nosec B603 B607
                       env=env or _GIT_ENV260)
        return r.returncode, r.stdout.strip(), r.stderr
    except (OSError, _sp260.SubprocessError) as e:
        return -1, "", repr(e)


# The race the review found, made still: the panel's tree with NO .git at the instant _gitc looks
# (renamed away), and a repository of the panel user's one level up, in its home. The old _gitc
# read the owner from .git, found none, and ran plain git as root; git walked up into the home's
# repository (whose config and hooks the panel writes) and, through SUDO_UID, trusted it.
_HOME260 = os.path.join(_TMP260, "home")
_PD260 = os.path.join(_HOME260, "linuxgsm-panel")
_repo260(_HOME260)
os.makedirs(_PD260)
_give_away260(_HOME260)
# The tree's owner: this account, or nobody on the root lane, where git (as root, running what the
# sudo stand-in hands it) is told to trust a repository that is not root's (a global config file).
_OWNER260 = _ME260 if os.geteuid() != 0 else _pwd260.getpwuid(65534).pw_name
_SAFE260 = os.path.join(_TMP260, "gitconfig-safe")
with open(_SAFE260, "w", encoding="utf-8") as _fh260:
    _fh260.write("[safe]\n\tdirectory = *\n")
_OWNED_ENV260 = dict(_GIT_ENV260, GIT_CONFIG_GLOBAL=_SAFE260) if os.geteuid() == 0 else _GIT_ENV260
_rc_a260, _out_a260, _err_a260 = _gitc260(_PD260, "rev-parse --show-toplevel", env=_OWNED_ENV260)
eq("_gitc r31: a root run with no .git in the panel's tree runs git as the tree's owner (sudo -u), "
   "never as root", [ln for ln in _err_a260.splitlines() if ln.startswith("SUDO ")], ["SUDO -u " + _OWNER260])
check("_gitc r31: ...and git stops at the tree (GIT_CEILING_DIRECTORIES): it never walks up into the "
      "panel user's home and uses the repository there", _rc_a260 != 0 and _out_a260 != _HOME260,
      "rc=%s out=%r err=%r" % (_rc_a260, _out_a260, _err_a260[-300:]))
# The same tree with its own .git: still the owner, and the tree's own repository.
_repo260(_PD260)
_give_away260(_PD260)
_rc_b260, _out_b260, _err_b260 = _gitc260(_PD260, "rev-parse --show-toplevel", env=_OWNED_ENV260)
eq("_gitc r31: with its .git back, the same call is the tree's own repository, as its owner",
   (_rc_b260, _out_b260, [ln for ln in _err_b260.splitlines() if ln.startswith("SUDO ")]),
   (0, os.path.realpath(_PD260), ["SUDO -u " + _OWNER260]))

# A link the panel user made where the tree should be, with no PANEL_USER to run it as: who owns
# it cannot be settled, so git does not run (the old _gitc followed the link and ran git as root).
_LINK260 = os.path.join(_TMP260, "linked-panel")
os.symlink(_PD260, _LINK260)
_rc_c260, _out_c260, _err_c260 = _gitc260(_LINK260, "rev-parse HEAD", panel_user="",
                                          extra="git() { echo GIT-RAN >&2; command git \"$@\"; }\n")
check("_gitc r31: a root run whose owner cannot be settled (a link, no panel account named) runs no git at all",
      _rc_c260 != 0 and "GIT-RAN" not in _err_c260 and _out_c260 == "",
      "rc=%s out=%r err=%r" % (_rc_c260, _out_c260, _err_c260[-300:]))

# Judged root's, but the folder that is opened is not root's (what a swap after the judgement
# leaves): root runs no git there. As root (the CI's root lane) the folder is given to nobody.
_SWAP260 = os.path.join(_TMP260, "swapped")
_repo260(_SWAP260)
_give_away260(_SWAP260)
_rc_d260, _out_d260, _err_d260 = _gitc260(_SWAP260, "rev-parse HEAD",
                                          extra="_r42i_tree_owner() { echo root; }\n")
check("_gitc r31: judged root's, a folder that is not root's when opened (no-follow) gets no git as root",
      _rc_d260 != 0 and _out_d260 == "" and "not root's" in _err_d260,
      "rc=%s out=%r err=%r" % (_rc_d260, _out_d260, _err_d260[-300:]))

# Root's own tree, as root: git runs there, with SUDO_UID/SUDO_GID/SUDO_USER removed (so git trusts
# a root-owned repository only, git-config(1) safe.directory). As root directly; otherwise inside a
# user namespace where this account is uid 0 (unshare -r), skipped by name where there is none.
_ROOTS260 = os.path.join(_TMP260, "roots")
_repo260(_ROOTS260)
_ROOT_GATE260 = "_gitc r31: root's own tree runs git as root, without SUDO_UID"
_root_env260 = dict(_GIT_ENV260, SUDO_UID="4242", SUDO_GID="4242", SUDO_USER="p260panel")
_root_script260 = ("set -uo pipefail\nPANEL_DIR=%s\nPANEL_USER=p260nobody\n" % _shlex260.quote(_ROOTS260)
                   + _GITC260 + "_gitc rev-parse --show-toplevel\n_gitc -c 'alias.penv=!env' penv\n")
_argv260 = (["bash", "-c", _root_script260] if os.geteuid() == 0 else
            ["unshare", "-r", "bash", "-c", _root_script260] if _shutil260.which("unshare") else None)
_r_e260 = None
if _argv260 is not None:
    try:
        _r_e260 = _sp260.run(_argv260, capture_output=True, text=True, timeout=60, env=_root_env260)  # nosec B603
    except (OSError, _sp260.SubprocessError):
        _r_e260 = None      # no answer: reported as a SKIP below, never as a pass
if _r_e260 is None or (_argv260 and _argv260[0] == "unshare" and "unshare:" in (_r_e260.stderr or "")):
    skip(_ROOT_GATE260, "no root and no user namespace here")
else:
    _lines_e260 = _r_e260.stdout.splitlines()
    _ran_e260 = _r_e260.returncode == 0 and bool(_lines_e260) and _lines_e260[0] == os.path.realpath(_ROOTS260)
    _sudo_e260 = sorted(ln.split("=", 1)[0] for ln in _lines_e260 if ln.startswith("SUDO_"))
    check("_gitc r31: root's own tree, as root, runs git there (opened no-follow, its .git root's)", _ran_e260,
          "rc=%s out=%r err=%r" % (_r_e260.returncode, _r_e260.stdout[:300], _r_e260.stderr[-300:]))
    eq("_gitc r31: ...with SUDO_UID, SUDO_GID and SUDO_USER removed from git's environment", _sudo_e260, [])
    # The same branch under its skip's own name: ci.yml's root step judges a skipped gate by that name.
    check(_ROOT_GATE260, _ran_e260 and _sudo_e260 == [], "ran=%s sudo=%s" % (_ran_e260, _sudo_e260))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. The web server: idle and slow connections, descriptors, the WebSocket
# ════════════════════════════════════════════════════════════════════════════════════════════════
_SERVE260 = r"""
import os, sys
os.environ["EVENTLET_NO_GREENDNS"] = "yes"
sys.path.insert(0, sys.argv[2])
mode = sys.argv[3]
import eventlet
if mode == "ws":
    eventlet.monkey_patch()
from flask import Flask
from panel.core import wsgi_serve
from panel.ops import socket_hooks

app = Flask("p260")
app.add_url_rule("/ok", "ok", lambda: "fine")
port = int(sys.argv[1])
if mode == "ws":
    # Socket.IO's heartbeat made short (a ping every second, a second to answer), the read timeout
    # left to io_seconds(), which the production server uses: about 2.7 s here.
    socket_hooks.LIMITS.update(ping_interval=1, ping_timeout=1)
    from flask_socketio import SocketIO
    SocketIO(app, async_mode="eventlet", **socket_hooks.LIMITS)
    wsgi_serve.serve(app, "127.0.0.1", port, idle_seconds=1)
elif mode == "fds":
    import resource
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, resource.getrlimit(resource.RLIMIT_NOFILE)[1]))
    wsgi_serve.serve(app, "127.0.0.1", port, idle_seconds=2, io_timeout=2)
else:
    wsgi_serve.serve(app, "127.0.0.1", port, idle_seconds=1, io_timeout=5)
"""
_OK260 = b"GET /ok HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"


def _free_port260():
    with _socket260.socket() as so:
        so.bind(("127.0.0.1", 0))
        return so.getsockname()[1]


def _get_ok260(port):
    """The status line of GET /ok on a fresh connection, b"" when there is no answer."""
    try:
        with _socket260.create_connection(("127.0.0.1", port), timeout=5) as so:
            so.sendall(_OK260)
            return so.recv(4096).split(b"\r\n")[0]
    except OSError:
        return b""


class _Server260:
    """wsgi_serve.serve in a child process on a free loopback port (`mode` picks the timeouts)."""

    def __init__(self, mode):
        self.port = _free_port260()
        # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
        self.proc = _sp260.Popen([_sys260.executable, "-c", _SERVE260, str(self.port), str(_ROOT260), mode],  # nosec B603
                                 stdout=_sp260.DEVNULL, stderr=_sp260.PIPE)
        deadline = _time260.monotonic() + 30
        self.ready = False
        while self.proc.poll() is None and _time260.monotonic() < deadline and not self.ready:
            self.ready = _get_ok260(self.port) == b"HTTP/1.1 200 OK"
            if not self.ready:
                _time260.sleep(0.2)

    def stop(self):
        if self.proc.poll() is None:
            self.proc.kill()
        return self.proc.communicate(timeout=10)[1].decode("utf-8", "replace")


def _closed_after260(port, send, limit):
    """Seconds until the server closes a connection that sent `send` and then nothing; None if not by `limit`."""
    try:
        with _socket260.create_connection(("127.0.0.1", port), timeout=limit) as so:
            t0 = _time260.monotonic()
            if send:
                so.sendall(send)
            while True:
                if not so.recv(4096):
                    return round(_time260.monotonic() - t0, 1)
    except OSError:
        return None


_srv_t260 = _Server260("timeouts")
try:
    _idle260 = _closed_after260(_srv_t260.port, b"", 10) if _srv_t260.ready else "not ready"
    _slow260 = (_closed_after260(_srv_t260.port, b"GET /ok HTTP/1.1\r\nHost: 127.0.0.1\r\n", 10)
                if _srv_t260.ready else "not ready")
    _after_t260 = _get_ok260(_srv_t260.port)
finally:
    _err_t260 = _srv_t260.stop()
# The idle time (1 s) well under the read timeout (5 s), so each close is told apart from the other.
check("web server r31: a connection that sends nothing is closed after the idle time (1 s here, the read timeout "
      "5 s; it waited for ever)", isinstance(_idle260, float) and _idle260 < 3, "closed after %r s" % (_idle260,))
check("web server r31: a request that stops part-way through its headers is closed after the read timeout "
      "(5 s here)", isinstance(_slow260, float) and 3 <= _slow260 < 8, "closed after %r s" % (_slow260,))
eq("web server r31: ...and it serves the next request, with no traceback logged for either close",
   (_after_t260, "Traceback" in _err_t260), (b"HTTP/1.1 200 OK", False))

# Out of descriptors: 64 here, and 80 idle connections. accept() raised EMFILE, eventlet re-raised it
# out of server() and the process ended. Now it waits; the idle connections time out, and it serves.
_srv_f260 = _Server260("fds")
_held260 = []
try:
    if _srv_f260.ready:
        for _ in range(80):
            try:
                _held260.append(_socket260.create_connection(("127.0.0.1", _srv_f260.port), timeout=5))
            except OSError:
                break
        _time260.sleep(1.0)
        _alive_mid260 = _srv_f260.proc.poll() is None
        _get_ok260(_srv_f260.port)   # a request while every descriptor is held: it may wait or fail, the server must stay up
        for _so260 in _held260:
            _so260.close()
        _deadline260 = _time260.monotonic() + 15
        _after_f260 = b""
        while _time260.monotonic() < _deadline260 and _after_f260 != b"HTTP/1.1 200 OK":
            _after_f260 = _get_ok260(_srv_f260.port)
            if _after_f260 != b"HTTP/1.1 200 OK":
                _time260.sleep(0.5)
    else:
        _alive_mid260, _starved260, _after_f260 = None, b"", b"not ready"
finally:
    for _so260 in _held260:
        _so260.close()
    _alive_end260 = _srv_f260.proc.poll() is None
    _err_f260 = _srv_f260.stop()
eq("web server r31: idle connections using every descriptor (EMFILE) do not end the server: it is still running, "
   "and serves again once they are gone", (len(_held260), _alive_mid260, _alive_end260, _after_f260),
   (80, True, True, b"HTTP/1.1 200 OK"))
check("web server r31: ...and says so in the log, once, without a traceback",
      _err_f260.count("cannot accept a connection (EMFILE)") == 1 and "Traceback" not in _err_f260,
      _err_f260[-600:])


def _ws_frame260(text):
    """A masked client text frame (RFC 6455 5.2) holding `text`."""
    data = text.encode()
    mask = os.urandom(4)
    head = bytes([0x81, 0x80 | len(data)]) if len(data) < 126 else bytes([0x81, 0x80 | 126]) + _struct260.pack("!H", len(data))
    return head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data))


def _ws_read260(so, buf):
    """One server frame from `so` (unmasked): (opcode, payload, rest of buf); (None, b"", b"") on a close."""
    def need(n):
        nonlocal buf
        while len(buf) < n:
            part = so.recv(4096)
            if not part:
                raise EOFError
            buf += part
    need(2)
    op, ln = buf[0] & 0x0F, buf[1] & 0x7F
    off = 2
    if ln == 126:
        need(4)
        ln, off = _struct260.unpack("!H", buf[2:4])[0], 4
    elif ln == 127:
        need(10)
        ln, off = _struct260.unpack("!Q", buf[2:10])[0], 10
    need(off + ln)
    return op, buf[off:off + ln], buf[off + ln:]


def _ws_upgrade260(so):
    """Ask for Socket.IO's WebSocket on `so`: (what was read past the 101, None) or (None, why not)."""
    nonce = _b64_260.b64encode(os.urandom(16))       # RFC 6455 4.1: a random 16-byte value, base64
    so.sendall(b"GET /socket.io/?EIO=4&transport=websocket HTTP/1.1\r\nHost: 127.0.0.1\r\n"
               b"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + nonce + b"\r\n"
               b"Sec-WebSocket-Version: 13\r\n\r\n")
    buf = b""
    while b"\r\n\r\n" not in buf:
        part = so.recv(4096)
        if not part:
            return None, "no upgrade"
        buf += part
    head, buf = buf.split(b"\r\n\r\n", 1)
    return (buf, None) if head.startswith(b"HTTP/1.1 101") else (None, head[:80].decode("latin-1"))


def _ws_session260(port, hold):
    """A Socket.IO WebSocket held for `hold` s, answering every ping: (pings seen, still open, why it ended)."""
    pings = 0
    try:
        so = _socket260.create_connection(("127.0.0.1", port), timeout=10)
    except OSError as e:
        return 0, False, "connect: %r" % e
    try:
        buf, refused = _ws_upgrade260(so)
        if refused:
            return 0, False, refused
        so.sendall(_ws_frame260("40"))
        end = _time260.monotonic() + hold
        while _time260.monotonic() < end:
            op, payload, buf = _ws_read260(so, buf)
            if op == 8:
                return pings, False, "server closed it"
            if payload == b"2":
                pings += 1
                so.sendall(_ws_frame260("3"))
        return pings, True, ""
    except EOFError:
        return pings, False, "connection closed"
    except OSError as e:
        return pings, False, repr(e)
    finally:
        so.close()


_srv_w260 = _Server260("ws")
try:
    _ws260 = _ws_session260(_srv_w260.port, 9) if _srv_w260.ready else (0, False, "not ready")
finally:
    _err_w260 = _srv_w260.stop()
check("web server r31: a Socket.IO WebSocket answering the heartbeat stays open for 9 s, over three times the "
      "read timeout (the console and terminal are not cut)", _ws260[1] and _ws260[0] >= 5,
      "pings=%s open=%s why=%s err=%s" % (_ws260[0], _ws260[1], _ws260[2], _err_w260[-400:]))
check("web server r31: the read timeout is longer than Socket.IO's heartbeat window (ping interval + timeout), "
      "with the panel's own settings and any others",
      all(_wsmod260.io_seconds(lim) > lim["ping_interval"] + lim["ping_timeout"]
          for lim in (_sh260.LIMITS, {"ping_interval": 1, "ping_timeout": 1})),
      "io=%r for %r" % (_wsmod260.io_seconds(), _sh260.LIMITS))
_units260 = _re260.findall(r"(?ms)^\[Service\]\n.*?^\[Install\]", _inst)
eq("web server r31: both unit templates (system and per-user) set LimitNOFILE, as written lines",
   [len(_re260.findall(r"(?m)^LimitNOFILE=8192$", u)) for u in _units260], [1, 1])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. SFTP keys: the proof to add one, the alerts, and every recovery path removes them
# ════════════════════════════════════════════════════════════════════════════════════════════════
import pyotp as _otp260  # noqa: E402

from panel.core.config import encrypt_secret as _enc260  # noqa: E402
from panel.db.models import AuditLog as _AL260, SftpKey as _Key260, User as _U260, UserSession as _US260  # noqa: E402
from panel.db.models import db as _db260  # noqa: E402
from panel.routes import admin_notifications as _an260  # noqa: E402
from panel.security import account_notices as _notices260, auth as _auth260  # noqa: E402
from panel.services import sftp_common as _sc260  # noqa: E402

_PW260 = "p260-Pass" + "word-long-enough-1"     # the fixture accounts' password, never a real one
_SECRET260 = _otp260.random_base32()


def _pubkey260():
    """A new Ed25519 public key line."""
    k = _sc260.host_key_from_text(_sc260.new_host_key_text())
    return "%s %s p260" % (k.get_name(), k.get_base64())


def _keys260(uid):
    with _p9.app_context():
        return _Key260.query.filter_by(user_id=uid).count()


def _plant_key260(uid):
    """One SFTP key on account `uid`, written directly (the add route is checked on its own above)."""
    line = _pubkey260()
    parsed = _sc260.parse_public_key(line, "planted")[0]
    with _p9.app_context():
        _db260.session.add(_Key260(user_id=uid, label="planted", key_type=parsed.key_type, key_blob=parsed.blob_b64,
                                   fingerprint=parsed.fingerprint))
        _db260.session.commit()


with _p9.app_context():
    _tfa260 = _U260(username="p260_tfa", password_hash=_auth260.hash_password(_PW260), is_active=True,
                    totp_secret=_enc260(_SECRET260), totp_enabled=True)
    _rec260 = _U260(username="p260_recover", password_hash=_tfa260.password_hash, is_active=True)
    _db260.session.add_all([_tfa260, _rec260])
    _db260.session.commit()
    _TFA260, _REC260 = _tfa260.id, _rec260.id

_alerts260 = []
try:
    _p9_patch(_notices260, "alert_credential_change", lambda user, what: _alerts260.append((user.username, what)))
    _c260 = _p9_client(_TFA260)
    _no_code260 = _c260.post("/account/sftp-keys/add", data={"public_key": _pubkey260(), "password": _PW260})
    _bad_code260 = _c260.post("/account/sftp-keys/add", data={"public_key": _pubkey260(), "password": _PW260,
                                                              "totp_code": "000000" if _otp260.TOTP(_SECRET260).now() != "000000" else "111111"})
    _n_refused260 = _keys260(_TFA260)
    _code260 = _otp260.TOTP(_SECRET260).now()
    _good260 = _c260.post("/account/sftp-keys/add", data={"public_key": _pubkey260(), "password": _PW260,
                                                          "totp_code": _code260})
    _n_good260 = _keys260(_TFA260)
    _replay260 = _c260.post("/account/sftp-keys/add", data={"public_key": _pubkey260(), "password": _PW260,
                                                            "totp_code": _code260})
    _n_replay260 = _keys260(_TFA260)
    with _p9.app_context():
        _kid260 = (_Key260.query.filter_by(user_id=_TFA260).first() or _Key260(id=0)).id
        _why260 = [r.detail for r in _AL260.query.filter_by(action="sftp_key_add", user_id=_TFA260, success=False)
                   .order_by(_AL260.id)]
    _rm260 = _c260.post("/account/sftp-keys/%d/remove" % _kid260)
    _changes260 = _p9_client(_TFA260).get("/account").get_data(as_text=True)
finally:
    _p9_restore_all()
eq("sftp keys r31: with 2FA on, adding a key needs a current code too: none, or a wrong one, adds nothing; the "
   "right one adds it; the same code again (replayed) adds nothing",
   (_n_refused260, _n_good260, _n_replay260, [r.status_code for r in (_no_code260, _bad_code260, _good260, _replay260)],
    _rm260.status_code), (0, 1, 1, [302] * 4, 200))
eq("sftp keys r31: ...each refusal audited with its reason", _why260,
   ["refused: wrong authenticator code", "refused: wrong authenticator code", "refused: replayed authenticator code"])
eq("sftp keys r31: adding and removing a key raise the credential_change alert (an administrator's account is "
   "alerted on the panel's channels)", [w.split(" (")[0] for _u, w in _alerts260], ["SFTP key added", "SFTP key removed"])
check("sftp keys r31: ...and both show in the account's own recent security changes",
      "SFTP key added" in _changes260 and "SFTP key removed" in _changes260,
      _changes260[_changes260.find('id="acct-changes"'):][:600])


def _recover260(how):
    """Plant a key on the recovery account, take the account back `how`; -> keys left."""
    with _p9.app_context():
        u = _db260.session.get(_U260, _REC260)
        # Epoch 0: part12's test client signs in with a plain id, which the loader accepts only then.
        u.is_active, u.must_change_password, u.auth_epoch = True, False, 0
        _db260.session.commit()
    _plant_key260(_REC260)
    before = _keys260(_REC260)
    try:
        if how == "password":
            _p9_client(_REC260).post("/account/password", data={
                "current_password": _PW260, "new_password": _PW260 + "-2", "confirm_password": _PW260 + "-2"})
            with _p9.app_context():
                u = _db260.session.get(_U260, _REC260)
                u.password_hash = _auth260.hash_password(_PW260)
                _db260.session.commit()
        elif how == "sessions":
            _p9_client(_REC260).post("/account/sessions/revoke")
        elif how in ("reset", "deactivate"):
            form = {_RESET_BOX260: "on"} if how == "reset" else {"display_name": "p260_recover"}
            with _p9.test_request_context("/users/%d/edit" % _REC260, method="POST", data=form):
                u = _db260.session.get(_U260, _REC260)
                if how == "reset":
                    _an260._apply_resets(u, [])
                else:
                    _an260._apply_profile_fields(u)       # no is_active in the form: deactivated
                _db260.session.commit()
    except Exception as e:  # noqa: BLE001 - recorded as the check's failure, not a crash of the part
        return before, "raised %r" % e
    return before, _keys260(_REC260)


_rec_results260 = {h: _recover260(h) for h in ("password", "sessions", "reset", "deactivate")}
eq("sftp keys r31: every way of taking an account back removes its SFTP keys: a password change, sign out "
   "everywhere, an admin's password reset, deactivation", _rec_results260,
   {"password": (1, 0), "sessions": (1, 0), "reset": (1, 0), "deactivate": (1, 0)})
with _p9.app_context():
    for _uid260 in (_TFA260, _REC260):
        _Key260.query.filter_by(user_id=_uid260).delete()
        _US260.query.filter_by(user_id=_uid260).delete()
        _db260.session.delete(_db260.session.get(_U260, _uid260))
    _db260.session.commit()


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. The user manager's folders are sign-in paths
# ════════════════════════════════════════════════════════════════════════════════════════════════
from types import SimpleNamespace as _NS260  # noqa: E402

from unit.part190 import _U190, _UNDO190, _Sb190, _crafted190, _missing190  # noqa: E402
from panel.ops.ssh_manager import files as _files260  # noqa: E402
from panel.services import game_restore as _grs260, sftp_files as _sftpf260  # noqa: E402

_UNITS260 = (".config/systemd/user/x.service", ".config/systemd/user/default.target.d/x.conf",
             ".config/systemd/user-generators/g", ".config/containers/systemd/x.container",
             ".config/containers/containers.conf", ".config/environment.d/x.conf",
             ".local/share/systemd/user/x.service", ".config/systemd", ".config", ".local", ".local/share")
eq("sign-in paths r31: the user manager's units, drop-ins, generators, environment and Quadlet files, and the "
   "folders above them, are sign-in paths by name", [n for n in _UNITS260 if not _files260._is_login_path(n)], [])
eq("sign-in paths r31: ...while a game's own files beside them are not (controls)",
   [_files260._is_login_path(n) for n in (".config/unity3d/prefs", ".local/share/Steam/x", ".configx",
                                          "serverfiles/.config/systemd/user/x.service", ".config/systemdx")],
   [False] * 5)
eq("sign-in paths r31: the file browser refuses to create a unit, make the folder, or rename a folder into "
   "~/.config (it would bring its own units) with the sign-in sentence",
   [_files260.create_refusal("p260u", ".config/systemd/user", "x.service", "file"),
    _files260.create_refusal("p260u", ".config", "systemd", "folder"),
    _files260.create_refusal("p260u", ".local/share", "systemd", "folder"),
    _files260.rename_refusal("p260u", "units", ".config")],
   [_files260.LOGIN_FILE_REFUSED] * 4)
_t260 = _NS260(user="p260u", selfname="p260srv")
eq("sign-in paths r31: the SFTP service refuses the same writes and new names",
   [_sftpf260._write_problem(_t260, ".config/containers/systemd/x.container", False),
    _sftpf260._write_problem(_t260, ".config/environment.d/x.conf", True),
    _sftpf260._new_name_problem(_t260, ".local/share/systemd")],
   [_files260.LOGIN_FILE_REFUSED] * 3)


def _host_guard260(resolved):
    """The host-side guard on a write whose path resolved to `resolved`: its exit status (13 refused)."""
    script = 'h=/home/p260u; p=%s; %s exit 0' % (_shlex260.quote(resolved), _files260._login_guard("/home/p260u", "p"))
    return _sp260.run(["bash", "-c", script], capture_output=True, text=True, timeout=30).returncode  # nosec B603 B607


eq("sign-in paths r31: on the host, a write that RESOLVES into a unit folder or onto a folder above one is "
   "refused (a link elsewhere in the home pointing there), and a game file beside them is not",
   [_host_guard260("/home/p260u/" + n) for n in (
       ".config/systemd/user/x.service", ".local/share/systemd/user/y", ".config/containers/systemd/z.container",
       ".config", ".config/unity3d/prefs")], [13, 13, 13, 13, 0])


def _units_restore260():
    """Restore an archive holding planted user units over a home with its own; -> what is left."""
    sb = _Sb190()
    try:
        # Two of the account's own: one a folder down (.config/systemd), one two down (.local/share/systemd),
        # which a walk only one folder deep would move away with .local/share.
        os.makedirs(os.path.join(sb.home, ".config/systemd/user"))
        os.makedirs(os.path.join(sb.home, ".local/share/systemd/user"))
        sb.put(".config/systemd/user/own.service", "own unit\n")
        sb.put(".local/share/systemd/user/own2.service", "own unit 2\n")
        planted = (".config/systemd/user/evil.service", ".config/containers/systemd/evil.container",
                   ".config/environment.d/evil.conf", ".local/share/systemd/user/evil.service")
        dirs = sorted({"/".join(n.split("/")[:i]) for n in planted + (".config/app/settings.ini",)
                       for i in range(1, n.count("/") + 1)})
        name = _crafted190(sb, [("././%s/" % d, _tarfile260.DIRTYPE, "") for d in dirs]
                           + [("././" + n, _tarfile260.REGTYPE, "") for n in planted + (".config/app/settings.ini",)])
        ready = sb.vet(name)[1][1]
        with open(os.path.join(sb.bdir, _UNDO190), "wb") as f:
            f.write(b"undo")
        out, rc = sb.run(_grs260.restore_script(_U190, _U190, name, ready["t0"], ready["need"], _UNDO190,
                                                busy_polls=1, members=ready["members"]))
        return (_grs260.restore_outcome(out, rc)[0], sb.read(".config/systemd/user/own.service"),
                sb.read(".local/share/systemd/user/own2.service"),
                [n for n in planted if os.path.lexists(os.path.join(sb.home, n))], sb.read(".config/app/settings.ini"))
    except Exception as e:  # noqa: BLE001 - recorded as the check's failure, not a crash of the part
        return ("raised %r" % e, None, None, None, None)
    finally:
        sb.gone()


if _missing190:
    skip("sign-in paths r31: a restore keeps the account's own user units", "missing tools: %s" % _missing190)
else:
    eq("sign-in paths r31: a restore of an archive holding user units, a Quadlet file, an environment.d file and a "
       "~/.local/share unit keeps the account's own units (one and two folders down), brings in none of them, and "
       "restores the game's own ~/.config file", _units_restore260(), ("done", "own unit\n", "own unit 2\n", [], ""))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. ufw rules with logging
# ════════════════════════════════════════════════════════════════════════════════════════════════
from unit.part135 import _REMOTE135, _TSREMOTE135, _Host135, _on135  # noqa: E402
from panel.ops.ssh_manager import firewall as _fw260, hosts as _hosts260  # noqa: E402


def _ufw_row260(to, action, frm, attribs="", comment=""):
    """One rule row as ufw 0.36 prints it (backend_iptables.get_status), without its `[ N]`."""
    return ("%-26s %-12s%-26s%s%s" % (to, action, frm, " (%s)" % attribs if attribs else "",
                                      " # %s" % comment if comment else "")).rstrip()


_LOG_ROWS260 = [_ufw_row260("22/tcp", "ALLOW IN", "Anywhere", "log"),
                _ufw_row260("22/tcp (v6)", "ALLOW IN", "Anywhere (v6)", "log")]
eq("ufw r31: a rule's (log) / (log-all) is read as its logging, not as part of From; a comment after it and the "
   "(v6) family are read as before, and an outbound rule's (log, out) too",
   [(_r["from"], _r["log"], _r["v6"], _r["comment"], _r["direction"]) for _r in map(_fw260._parse_ufw_rule, (
       _ufw_row260("22/tcp", "ALLOW IN", "Anywhere", "log"),
       _ufw_row260("80/tcp (v6)", "LIMIT IN", "Anywhere (v6)", "log-all", "web"),
       _ufw_row260("53", "ALLOW OUT", "Anywhere", "log, out"),
       _ufw_row260("27015", "ALLOW IN", "Anywhere (v6)"),
       _ufw_row260("25565", "ALLOW IN", "Anywhere", "", "kept (log)")))],
   [("Anywhere", "log", False, "", "IN"), ("Anywhere", "log-all", True, "web", "IN"), ("Anywhere", "log", False, "", "OUT"),
    ("Anywhere", "", True, "", "IN"), ("Anywhere", "", False, "kept (log)", "IN")])


def _ssh_mode260(rows):
    host = _Host135(rules=rows, ts=(True, True))
    return _on135(host, _hosts260.remote_public_ssh_status, _REMOTE135).get("mode")


eq("ufw r31: public SSH opened by a logged rule reads as open (it read 'off', the tailnet-only reassurance), and "
   "a logged LIMIT as rate-limited, IPv4 and IPv6",
   [_ssh_mode260(_LOG_ROWS260), _ssh_mode260([_ufw_row260("22/tcp", "LIMIT IN", "Anywhere", "log-all"),
                                              _ufw_row260("22/tcp (v6)", "LIMIT IN", "Anywhere (v6)", "log-all")]),
    _ssh_mode260([_ufw_row260("22/tcp (v6)", "ALLOW IN", "Anywhere (v6)", "log")])],
   ["allow", "limit", "allow"])
# Disable public SSH and Close port 22 with the logged rule still there after their deletes (ufw deletes
# by spec, and `delete allow 22/tcp` does not match a rule with logging): each says it is still open. The
# host is reached over Tailscale, so the lock-out guard (the panel's own way in) does not answer first.
_off260 = _on135(_Host135(rules=list(_LOG_ROWS260), ts=(True, True)), _hosts260.remote_set_public_ssh,
                 _TSREMOTE135, "off")
_close260 = _on135(_Host135(rules=list(_LOG_ROWS260), ts=(True, True)), _hosts260.remote_ufw_close_port,
                   _TSREMOTE135, 22, "tcp", True)
check("ufw r31: Disable public SSH does not answer done while a logged rule still opens SSH: it reads the rule "
      "back and names it", not _off260[0] and "still reports it as open" in str(_off260[1])
      and "(log)" in str(_off260[1]), str(_off260))
check("ufw r31: ...nor does Close port 22", not _close260[0], str(_close260))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. World reset's arithmetic scan
# ════════════════════════════════════════════════════════════════════════════════════════════════
from panel.services import world_reset as _wwr260  # noqa: E402

# Evaluated as arithmetic, `port` is itself evaluated, and a value of "port=7" sets it: each of these
# lines may set a key it never spells, so the reader refuses it.
_ARITH260 = ['other="${a[port]}"', 'other="${a:port}"', 'other="$((port))"', 'other="$[port]"',
             'other="${$:port}"', 'other="${-:port}"', 'other="${a:-${b[port]}}"', 'other="${#a[port]}"']
_PLAIN260 = ['other="-port ${port}"', 'other="${a:-x} ${port}"', 'other="$port[1]"', 'other="${a:-$b[1]} ${port}"']
eq("world reset r31: every arithmetic context is refused, as a line that may set a key it does not spell "
   "(subscript, offset, $((…)), $[…], the PID's and the flags' offset, one nested in a default, a length's subscript)",
   [_wwr260._wwr_assigned(ln) for ln in _ARITH260], [None] * len(_ARITH260))
eq("world reset r31: ...and a line that only names or expands the key assigns only its own name (controls)",
   [_wwr260._wwr_assigned(ln) for ln in _PLAIN260], [["other"]] * len(_PLAIN260))


def _cfg_seconds260(n):
    """The fastest of three runs of _wwr_cfg_key over a config holding a value of `n` `${a}` expansions."""
    texts = ['port="27015"\nother="%s port"\n' % ("${a}" * n)]
    best = None
    for _ in range(3):
        t0 = _time260.perf_counter()
        _wwr260._wwr_cfg_key(texts, "port")
        took = _time260.perf_counter() - t0
        best = took if best is None else min(best, took)
    return best


# Quadruple the value: linear time grows about four-fold, quadratic sixteen-fold (8,000 -> 32,000 took
# 0.2 s -> 2.7 s before). 8 is the bar between them, with 50 ms of slack for a busy machine.
_t1_260, _t4_260 = _cfg_seconds260(8000), _cfg_seconds260(32000)
check("world reset r31: a config value of many expansions is read in linear time (8,000 -> 32,000: under 8x "
      "and 50 ms of slack; it grew sixteen-fold)", _t4_260 < 8 * _t1_260 + 0.05,
      "%.4f s -> %.4f s" % (_t1_260, _t4_260))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 7. Backup encryption: AES-256-GCM under Argon2id, the passphrase floor
# ════════════════════════════════════════════════════════════════════════════════════════════════
import io as _io260  # noqa: E402
import json as _json260  # noqa: E402

from cryptography.fernet import Fernet as _Fernet260  # noqa: E402

from panel.ops import backup as _bk260  # noqa: E402

_BKD260 = os.path.join(_TMP260, "bk")
os.makedirs(_BKD260)
_PHRASE260 = "p260 backup pass" + "phrase, long enough"   # a fixture passphrase, never a real one
_PLAIN260 = os.path.join(_BKD260, "plain.tar.gz")
with _tarfile260.open(_PLAIN260, "w:gz") as _tar260:
    for _m260 in ("panel.db", "config.json", "secret_key", "cred_key"):
        _ti260 = _tarfile260.TarInfo(_m260)
        _tar260.addfile(_ti260, _io260.BytesIO(b""))


def _bk_open260(path, phrase=_PHRASE260):
    """_decrypt_archive's answer for `path`, and the members it opens to (None when refused)."""
    out = os.path.join(_BKD260, "out.tar.gz")
    ok, why = _bk260._decrypt_archive(path, out, phrase)
    if not ok:
        return why, None
    with _tarfile260.open(out, "r:gz") as t:
        return "", sorted(t.getnames())


def _bk_head260(path):
    with open(path, "rb") as fh:
        body = fh.read()
    return body[:8], _json260.loads(body[8:body.index(b"\n", 8)].decode())


_V2_260 = os.path.join(_BKD260, "new.tar.gz.enc")
_bk260._encrypt_archive(_PLAIN260, _V2_260, _PHRASE260)
_magic260, _head260 = _bk_head260(_V2_260)
eq("backup enc r31: a new encrypted backup is version 2: AES-256-GCM, its key from Argon2id at m=47104 KiB, t=1, "
   "p=1, a 16-byte salt", (_magic260, _head260.get("cipher"), _head260.get("kdf"), _head260.get("m"), _head260.get("t"),
                           _head260.get("p"), len(_b64_260.b64decode(_head260.get("salt", "")))),
   (b"LGSMBK2\n", "aes-256-gcm", "argon2id", 47104, 1, 1, 16))
eq("backup enc r31: ...it opens with the passphrase to the four members, and not with another one",
   (_bk_open260(_V2_260), _bk_open260(_V2_260, _PHRASE260 + "x")[0]),
   (("", ["config.json", "cred_key", "panel.db", "secret_key"]), _bk260._R16C_KEY_DID_NOT_OPEN))
# The header is authenticated: a field added to it (which changes nothing the key is derived from)
# fails the tag like a changed byte of data.
with open(_V2_260, "rb") as _fh260:
    _v2body260 = _fh260.read()
_nl260 = _v2body260.index(b"\n", 8)
_tamper260 = os.path.join(_BKD260, "tampered-head.enc")
with open(_tamper260, "wb") as _fh260:
    _fh260.write(_v2body260[:_nl260 - 1] + b',"x":1}' + _v2body260[_nl260:])
eq("backup enc r31: a header changed without touching what the key comes from fails to open (it is the "
   "associated data)", _bk_open260(_tamper260), (_bk260._R16C_KEY_DID_NOT_OPEN, None))

# Version 1, as every backup before this was written: Fernet under scrypt (cheapest n, to keep it quick).
_salt260 = os.urandom(16)
_v1head260 = _json260.dumps({"kdf": "scrypt", "n": 2 ** 12, "r": 8, "p": 1,
                             "salt": _b64_260.b64encode(_salt260).decode()}).encode()
_V1_260 = os.path.join(_BKD260, "old.tar.gz.enc")
with open(_PLAIN260, "rb") as _fh260, open(_V1_260, "wb") as _out260:
    _out260.write(_bk260._ENC_MAGIC + _v1head260 + b"\n"
                  + _Fernet260(_bk260._derive_key(_PHRASE260, _salt260, n=2 ** 12, r=8, p=1)).encrypt(_fh260.read()))
eq("backup enc r31: a version-1 backup (Fernet under scrypt) still opens, so every older backup restores",
   _bk_open260(_V1_260), ("", ["config.json", "cred_key", "panel.db", "secret_key"]))
eq("backup enc r31: an uploaded backup of either version is taken as an encrypted one",
   [_bk260.upload_refusal(_V2_260), _bk260.upload_refusal(_V1_260)], [("", True), ("", True)])


def _v2_crafted260(**head):
    """A version-2 file whose header asks for `head` (merged over this panel's own), with junk after it."""
    h = {"cipher": "aes-256-gcm", "kdf": "argon2id", "m": 47104, "t": 1, "p": 1,
         "salt": _b64_260.b64encode(b"s" * 16).decode()}
    h.update(head)
    path = os.path.join(_BKD260, "crafted.enc")
    with open(path, "wb") as fh:
        fh.write(_bk260._ENC_MAGIC2 + _json260.dumps(h).encode() + b"\n" + b"\0" * 64)
    return path


_derived260 = []


def _fake_argon260(*a):
    """Argon2id's stand-in: records (m, t, p) and answers a key that opens nothing."""
    _derived260.append(a[2:])
    return b"\0" * 32


try:
    _p9_patch(_bk260, "_argon2id", _fake_argon260)
    _costly260 = [_bk_open260(_v2_crafted260(**kw))[0] for kw in (
        {"m": 2 * 47104 + 1}, {"t": 6}, {"p": 3}, {"m": 2 * 47104, "t": 3}, {"salt": _b64_260.b64encode(b"s" * 8).decode()},
        {"kdf": "scrypt"}, {"cipher": "aes-128-cbc"})]
    _within260 = _bk_open260(_v2_crafted260(m=19456, t=2))[0]
finally:
    _p9_restore_all()
eq("backup enc r31: a version-2 header asking for more memory, time, lanes or total work than the bound, a short "
   "salt, or another scheme is refused before anything is derived",
   (_costly260, _derived260[:-1]),
   (["The encrypted backup's header asks for parameters this panel will not use."] * 5
    + ["This backup uses an encryption scheme this panel does not know."] * 2, []))
eq("backup enc r31: ...while OWASP's other listed configuration (19 MiB, t=2) is derived and then fails the tag "
   "(control)", (_within260, _derived260[-1:]), (_bk260._R16C_KEY_DID_NOT_OPEN, [(19456, 2, 1)]))

# The passphrase floor: 15.
_short_set260 = None
try:
    _bk260.set_passphrase("fourteen chars")
except ValueError as _e260:
    _short_set260 = str(_e260)
except Exception as _e260:  # noqa: BLE001 - recorded as the check's failure
    _short_set260 = "raised %r" % _e260
_pp260 = []
try:
    _p9_patch(_bk260, "set_passphrase", _pp260.append)
    _r14_260 = _p9_client(P9_ADMIN).post("/api/panel/backup/settings", json={"passphrase": "f" * 14})   # one short of the 15-character floor
finally:
    _p9_restore_all()
eq("backup enc r31: a passphrase of 14 characters is refused by the helper and by the route (OWASP: 15 without "
   "MFA), and nothing is set", (_short_set260, _r14_260.status_code, _pp260),
   ("Backup passphrase must be at least 15 characters.", 400, []))
eq("backup enc r31: a stored passphrase set while the floor was 12 is flagged for the card's note; a long one, "
   "and none, are not", [_bk260._passphrase_short({"backup_passphrase": _enc260(p)}) if p else
                         _bk260._passphrase_short({}) for p in ("twelve chars", _PHRASE260, "")], [True, False, False])

_shutil260.rmtree(_TMP260, ignore_errors=True)
