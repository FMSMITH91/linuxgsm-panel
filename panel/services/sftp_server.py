"""The panel's SFTP service: its own process, started and stopped by the panel (sftp_broker.py).

    python -m panel.services.sftp_server          (the panel starts it; never by hand)

Why a process of its own: the panel is one eventlet hub, and a blocking descriptor or a long
CPU-bound loop there stalls every page and the live console (memory one-greenlet-per-descriptor).
SSH packet crypto for a multi-gigabyte transfer is exactly such a loop. Here it is plain threads in
a separate interpreter that never imports eventlet's monkey patching, so a transfer can only ever
cost the panel CPU time, never the hub.

What it decides itself: the SSH protocol (paramiko in server mode, the algorithms in
sftp_common), which folder of the virtual top level a path is in, that every path stays inside the
game account's home once links are resolved, the panel's file-name rules, and the upload size cap
and free space. Everything about WHO may do WHAT it asks the panel over a socket on every request:
sign-in (keys, password and authenticator code, the throttles and lockouts the web sign-in uses),
which servers a user may edit, and the audit rows. So a permission removed in the panel, a user
deactivated or signed out everywhere, takes effect on the next request (OWASP Authorization Cheat
Sheet, "Validate the Permissions on Every Request"). The one exception is a file already open: its
reads and writes re-ask at most once a second (AUTHZ_HOLD).

The files themselves are reached through sftp_backend: the host's own sftp-server, run as the game
account, so the operating system has the last word on every byte.

Lifetime: the panel holds this process's stdin and a socket pair. Either closing (the panel stopped,
crashed or was killed) ends this process within a second (_watch_lifeline).
"""
import base64
import json
import logging
import os
import posixpath
import signal
import socket
import stat as _stat
import sys
import threading
import time

import paramiko
from paramiko import (AUTH_FAILED, AUTH_SUCCESSFUL, OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED, OPEN_SUCCEEDED,
                      SFTP_BAD_MESSAGE, SFTP_FAILURE, SFTP_NO_SUCH_FILE, SFTP_OK, SFTP_OP_UNSUPPORTED,
                      SFTP_PERMISSION_DENIED, InteractiveQuery, SFTPAttributes, SFTPServer, SFTPServerInterface,
                      ServerInterface)
from paramiko.sftp import CMD_CLOSE

from panel.services import sftp_backend as bk
from panel.services import sftp_common as sc
# Defined in sftp_files, never here: this module runs as __main__, and a class it defined would be a
# different class from the one the other modules import by name, so their raise would escape its except.
from panel.services.sftp_files import AUTHZ_HOLD, DENIED, Files, Refused  # noqa: F401 - AUTHZ_HOLD for readers

_log = logging.getLogger("panel.sftp")

MAX_AUTH_TRIES = 6           # OpenSSH's MaxAuthTries default
LOGIN_GRACE = 60             # seconds to sign in (OpenSSH's LoginGraceTime is 120)
MAX_CONNECTIONS = 64
MAX_UNAUTH_PER_ADDRESS = 10
STAGE_MAX = 1024 * 1024      # a LinuxGSM config is checked whole before it is written: at most this
WINDOW = 4 * 1024 * 1024     # the SSH channel window offered to clients




# ── The panel ──────────────────────────────────────────────────────────────────────────────────
class Panel:
    """Request/response over the socket the panel handed this process: one JSON line each way."""

    def __init__(self, sock):
        """The panel at the far end of `sock`."""
        self._sock = sock
        self._rfile = sock.makefile("rb")             # buffered: one request is in flight at a time
        self._lock = threading.Lock()
        self._next = 0

    def ask(self, request, timeout=60):
        """Send `request` (a dict) and return the panel's answer; {} when the panel did not answer."""
        with self._lock:
            self._next += 1
            request = dict(request, id=self._next)
            try:
                self._sock.settimeout(timeout)
                self._sock.sendall(json.dumps(request).encode("utf-8") + b"\n")
                while True:
                    line = self._rfile.readline(1024 * 1024)
                    if not line:
                        _die("the panel closed its socket")
                    reply = json.loads(line)
                    if reply.get("id") == self._next:
                        return reply
            except (OSError, ValueError):
                _log.warning("the panel did not answer an SFTP request")
                return {}


def _die(why):
    _log.warning("SFTP service stopping: %s", why)
    os._exit(0)


# ── One signed-in connection ───────────────────────────────────────────────────────────────────
class Connection(ServerInterface):
    """paramiko's server interface for one client connection: sign-in, then the sftp subsystem only."""

    def __init__(self, service, ip):
        """A new connection from `ip`, not signed in."""
        self.service, self.ip = service, ip
        self.tries = 0
        self.counted = False        # a password attempt the panel already counted as a failure
        self.offered = False
        self.last_why = ""
        self.who = ""
        self.user = None            # {"uid", "epoch", "name", "method", "detail"} once signed in
        self._pending = None
        self._kbd_name = None

    def get_allowed_auths(self, username):
        """Keys always; the password and code too when the Settings card allows them."""
        return "publickey,keyboard-interactive" if self.service.cfg.get("password") else "publickey"

    def check_auth_none(self, username):
        """No sign-in without a credential."""
        return AUTH_FAILED

    def check_auth_password(self, username, password):
        """A bare password is never enough: keyboard-interactive asks for the code with it."""
        self.who = username
        return AUTH_FAILED

    def _spend_try(self, username):
        self.tries += 1
        self.who = username
        if self.tries > MAX_AUTH_TRIES:
            return False
        return True

    def check_auth_publickey(self, username, key):
        """Whether `key` is one of `username`'s keys and the account may sign in now (the panel decides)."""
        if not self._spend_try(username):
            return AUTH_FAILED
        self.offered = True
        reply = self.service.panel.ask({"op": "auth_key", "ip": self.ip, "username": username,
                                        "type": key.get_name(),
                                        "blob": base64.b64encode(key.asbytes()).decode("ascii")})
        if not reply.get("ok"):
            self.last_why = reply.get("why") or self.last_why
            return AUTH_FAILED
        self._pending = {"uid": reply["uid"], "epoch": reply["epoch"], "name": reply["name"],
                         "method": "publickey", "detail": reply.get("detail", "")}
        return AUTH_SUCCESSFUL

    def check_auth_interactive(self, username, submethods):
        """Ask for the password and the authenticator code, when the Settings card allows them."""
        if not self.service.cfg.get("password") or not self._spend_try(username):
            return AUTH_FAILED
        self._kbd_name = username
        return InteractiveQuery("", "", ("Password: ", False), ("Verification code: ", True))

    def check_auth_interactive_response(self, responses):
        """The panel checks the password and the code, counting the attempt as the web sign-in does."""
        name, self._kbd_name = self._kbd_name, None
        if name is None or len(responses) != 2:
            return AUTH_FAILED
        reply = self.service.panel.ask({"op": "auth_kbd", "ip": self.ip, "username": name,
                                        "password": responses[0], "code": responses[1]}, timeout=120)
        if not reply.get("ok"):
            self.counted = True
            return AUTH_FAILED
        self._pending = {"uid": reply["uid"], "epoch": reply["epoch"], "name": reply["name"],
                         "method": "keyboard-interactive", "detail": "password and authenticator code"}
        return AUTH_SUCCESSFUL

    def signed_in(self):
        """The signed-in user (paramiko has accepted a credential), or None."""
        t = getattr(self, "transport", None)
        if self.user is None and self._pending is not None and t is not None and t.is_authenticated():
            self.user = self._pending
        return self.user

    def check_channel_request(self, kind, chanid):
        """A session channel only, and only once signed in."""
        if kind == "session" and self.signed_in() is not None:
            return OPEN_SUCCEEDED
        return OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_subsystem_request(self, channel, name):
        """The sftp subsystem only: no shell, no command, no forwarding."""
        if name != "sftp" or self.signed_in() is None:
            return False
        return super().check_channel_subsystem_request(channel, name)


# ── The virtual file system ────────────────────────────────────────────────────────────────────
class Target:
    """One game server as the panel described it for this request: where its files are, and how."""

    def __init__(self, reply):
        """The server the panel's authz `reply` describes."""
        self.sid = reply["sid"]
        self.name = reply["name"]
        self.user = reply["user"]
        self.selfname = reply.get("selfname") or reply["user"]
        self.home = reply["home"]
        self.transport = reply["transport"]
        self.remote_id = reply.get("remote_id")
        self.key = (self.sid, self.user, self.home, self.transport, self.remote_id)


class VirtualSftp(SFTPServerInterface):
    """The top level is one folder per game server the user may edit; each maps to that account's home."""

    def __init__(self, server, *args, **kwargs):
        """The file system of one signed-in connection (`server`)."""
        super().__init__(server, *args, **kwargs)
        self.conn = server
        self.service = server.service
        self.backends = {}          # sid -> (Target.key, Backend, real home)
        self.lock = threading.Lock()
        self.open_count = 0

    # ── session ──
    def session_started(self):
        """Audit the sign-in once the client opens SFTP."""
        u = self.conn.signed_in()
        self.service.panel.ask({"op": "auth_done", "ip": self.conn.ip, "uid": u["uid"],
                                "method": u["method"], "detail": u["detail"]})

    def session_ended(self):
        """Close every game host connection this session opened."""
        with self.lock:
            backends, self.backends = self.backends, {}
        for _key, backend, _real in backends.values():
            backend.close()

    # ── the panel's answers ──
    def ask_folder(self, folder, write):
        u = self.conn.signed_in()
        reply = self.service.panel.ask({"op": "authz", "uid": u["uid"], "epoch": u["epoch"],
                                        "folder": folder, "write": bool(write), "ip": self.conn.ip})
        if not reply.get("ok"):
            if reply.get("gone"):
                raise Refused(SFTP_NO_SUCH_FILE, "No such file")
            raise Refused(SFTP_PERMISSION_DENIED, reply.get("reason") or DENIED)
        return Target(reply)

    def _folders(self):
        u = self.conn.signed_in()
        reply = self.service.panel.ask({"op": "servers", "uid": u["uid"], "epoch": u["epoch"]})
        if not reply.get("ok"):
            raise Refused(SFTP_PERMISSION_DENIED, reply.get("reason") or DENIED)
        return reply.get("folders") or []

    def audit(self, target, action, detail, success=True):
        """One audit row about `target`, written by the panel."""
        u = self.conn.signed_in()
        self.service.panel.ask({"op": "audit", "uid": u["uid"], "ip": self.conn.ip, "sid": target.sid,
                                "action": action, "detail": "SFTP: " + detail, "success": bool(success)})

    # ── paths ──
    @staticmethod
    def split(path):
        """(folder, rest) of a client path: '/' -> ('', ''); '/A/b/c' -> ('A', 'b/c'). Never '..' above /."""
        norm = posixpath.normpath("/" + (path or "").replace("\x00", ""))
        parts = norm.lstrip("/").split("/", 1)
        if parts == [""]:
            return "", ""
        return parts[0], parts[1] if len(parts) > 1 else ""

    def backend(self, target):
        """The open Backend for `target` (started on first use) and its real home."""
        with self.lock:
            have = self.backends.get(target.sid)
            if have is not None and have[0] == target.key and have[1].dead is None:
                return have[1], have[2]
        if have is not None:
            have[1].close()
        backend = self.service.connect(target)
        try:
            real_home = backend.realpath(target.home)
        except bk.BackendError:
            backend.close()
            raise Refused(SFTP_FAILURE, "The server's files cannot be reached right now.")
        with self.lock:
            self.backends[target.sid] = (target.key, backend, real_home)
        return backend, real_home

    @staticmethod
    def inside(path, homes):
        """Whether `path` is one of `homes` or below one (whole components compared)."""
        return any(path == h or path.startswith(h.rstrip("/") + "/") for h in homes)

    def resolve(self, path, write=False, follow=True):
        """(target, backend, the host path to use, the path relative to the home) for a client path.

        The host resolves every link (sftp-server's realpath); a path that resolves outside the
        game account's home is refused (OWASP Path Traversal Prevention Cheat Sheet, "Validate the
        Resolved Path"). `follow=False` resolves only the folder, for what acts on a link itself
        (remove, rename, lstat). Raises Refused.
        """
        folder, rest = self.split(path)
        if not folder:
            raise Refused(SFTP_PERMISSION_DENIED, DENIED)
        target = self.ask_folder(folder, write)
        backend, real_home = self.backend(target)
        lexical = posixpath.join(target.home, rest) if rest else target.home
        homes = (target.home, real_home)
        try:
            real = self._host_path(backend, lexical, follow or not rest)
        except bk.BackendError as exc:
            raise Refused(exc.code if exc.code in (SFTP_NO_SUCH_FILE, SFTP_PERMISSION_DENIED) else SFTP_FAILURE,
                          str(exc)) from exc
        if not self.inside(real, homes):
            raise Refused(SFTP_PERMISSION_DENIED, "That path leads outside the server's folder.")
        base = real_home if self.inside(real, (real_home,)) else target.home
        rel = posixpath.relpath(real, base)
        return target, backend, real, ("" if rel == "." else rel)

    @staticmethod
    def _host_path(backend, lexical, follow):
        if follow:
            try:
                return backend.realpath(lexical)
            except bk.BackendError as exc:
                if exc.code != bk.NO_SUCH_FILE:
                    raise
            # An older sftp-server refuses a missing last name: resolve the folder, and refuse a
            # link there that could not be resolved (where a create through it would land is unknown).
            try:
                a = backend.stat(lexical, follow=False)
            except bk.BackendError as exc:
                if exc.code != bk.NO_SUCH_FILE:
                    raise
                a = None
            if a is not None and _stat.S_ISLNK(a.get("mode", 0)):
                raise bk.BackendError(bk.PERMISSION_DENIED, "That link leads nowhere the panel can check.")
        parent = backend.realpath(posixpath.dirname(lexical))
        return posixpath.join(parent, posixpath.basename(lexical))

    # ── answers ──
    def attrs_for(self, name, a):
        """The SFTPAttributes the client is sent for a backend attribute dict."""
        out = SFTPAttributes()
        out.filename = name
        if "size" in a:
            out.st_size = a["size"]
        if "uid" in a:
            out.st_uid, out.st_gid = a["uid"], a["gid"]
        if "mode" in a:
            out.st_mode = a["mode"]
        if "mtime" in a:
            out.st_atime, out.st_mtime = a["atime"], a["mtime"]
        return out

    def _root_attrs(self, name="/"):
        out = SFTPAttributes()
        out.filename = name
        out.st_mode = _stat.S_IFDIR | 0o555
        out.st_size = 0
        out.st_mtime = out.st_atime = int(time.time())
        return out

    def list_folder(self, path):
        """The top level (the servers' folders), or a folder's entries as the game account sees them."""
        try:
            folder, _rest = self.split(path)
            if not folder:
                return [self._root_attrs(f) for f in self._folders()]
            _target, backend, real, _rel = self.resolve(path)
            return [self.attrs_for(n, a) for n, a in backend.listdir(real)]
        except Refused as r:
            return r.answer()
        except bk.BackendError as exc:
            return (exc.code, str(exc))

    def stat(self, path):
        """Attributes of `path`, a final link followed."""
        return self._stat(path, True)

    def lstat(self, path):
        """Attributes of `path` itself."""
        return self._stat(path, False)

    def _stat(self, path, follow):
        try:
            folder, rest = self.split(path)
            if not folder:
                return self._root_attrs()
            _t, backend, real, _rel = self.resolve(path, follow=follow or not rest)
            return self.attrs_for(posixpath.basename(path), backend.stat(real, follow=follow))
        except Refused as r:
            return r.answer()
        except bk.BackendError as exc:
            return (exc.code, str(exc))

    def canonicalize(self, path):
        """The client's path made absolute and normalised (the virtual tree has no links of its own)."""
        folder, rest = self.split(path)
        return "/" + "/".join(p for p in (folder, rest) if p)

    def open(self, path, flags, attr):
        """Open a file: for reading with view rights, for writing with edit rights and the panel's rules."""
        try:
            return self.service.files.open(self, path, flags, attr)
        except Refused as r:
            return r.answer()
        except bk.BackendError as exc:
            return (exc.code, str(exc))

    def remove(self, path):
        """Delete a file (a link itself, never what it points at)."""
        return self.service.files.change(self, "remove", path)

    def rmdir(self, path):
        """Delete an empty folder."""
        return self.service.files.change(self, "rmdir", path)

    def mkdir(self, path, attr):
        """Make a folder."""
        return self.service.files.change(self, "mkdir", path, attr=attr)

    def rename(self, oldpath, newpath):
        """Move or rename within one server's folder; never replaces what is there."""
        return self.service.files.change(self, "rename", oldpath, new=newpath)

    def posix_rename(self, oldpath, newpath):
        """As rename: an existing name is never replaced."""
        return self.rename(oldpath, newpath)

    def chattr(self, path, attr):
        """Change a file's permission bits or times (never its owner, never setuid/setgid/sticky)."""
        return self.service.files.change(self, "chattr", path, attr=attr)

    def symlink(self, target_path, path):
        """Links are not made over SFTP: one could lead out of the server's folder."""
        return (SFTP_OP_UNSUPPORTED, "Links cannot be made over SFTP.")

    def readlink(self, path):
        """Where a link leads, as a path in the virtual tree, when it stays in the server's folder."""
        try:
            folder, _rest = self.split(path)
            _t, backend, link, _r = self.resolve(path, follow=False)
            if not _stat.S_ISLNK(backend.stat(link, follow=False).get("mode", 0)):
                return (SFTP_FAILURE, "Not a link")
            rel = self.resolve(path)[3]
            return "/" + "/".join(p for p in (folder, rel) if p)
        except Refused as r:
            return r.answer()
        except bk.BackendError as exc:
            return (exc.code, str(exc))


class PanelSftpServer(SFTPServer):
    """paramiko's SFTP subsystem, with a refusal's own text sent to the client and check-file off."""

    def _send_status(self, request_number, code, desc=None):
        if isinstance(code, tuple):
            code, desc = code
        super()._send_status(request_number, code, desc)

    def _check_file(self, request_number, msg):
        # Hashing a file with MD5 or SHA-1 on request is not offered.
        self._send_status(request_number, SFTP_OP_UNSUPPORTED)

    def _process(self, t, request_number, msg):
        # A file's CLOSE answers with its close(): paramiko answers OK whatever close() found, and an
        # upload's last failure (a write the host refused, a LinuxGSM config refused whole) is only
        # known there. Everything else is paramiko's own handling.
        if t != CMD_CLOSE:
            return super()._process(t, request_number, msg)
        handle = msg.get_binary()
        if handle in self.folder_table:
            del self.folder_table[handle]
            return self._send_status(request_number, SFTP_OK)
        if handle in self.file_table:
            return self._send_status(request_number, self.file_table.pop(handle).close() or SFTP_OK)
        return self._send_status(request_number, SFTP_BAD_MESSAGE, "Invalid handle")


# ── The service ────────────────────────────────────────────────────────────────────────────────
class Service:
    """The listening sockets, the connections, and how a game server's files are reached."""

    def __init__(self, panel, cfg):
        """The service with the panel's settings `cfg`, not yet listening."""
        self.panel, self.cfg = panel, cfg
        self.files = Files(cfg)
        self.host_key = sc.host_key_from_text(cfg["host_key"])
        self._lock = threading.Lock()
        self._conns = 0
        self._unauth = {}
        self._db_app = None

    # ── listening ──
    def listen(self):
        """Bind every configured address; [(addr, port)] bound. Raises OSError when none could be."""
        socks, bound, errors = [], [], []
        for addr in self.cfg["binds"]:
            fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
            s = socket.socket(fam, socket.SOCK_STREAM)
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if fam == socket.AF_INET6:
                    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                s.bind((addr, self.cfg["port"]))
                s.listen(64)
            except OSError as exc:
                s.close()
                errors.append("%s: %s" % (addr, exc.strerror or exc))
                continue
            socks.append(s)
            bound.append([addr, self.cfg["port"]])
        if not socks:
            raise OSError("; ".join(errors) or "no address to listen on")
        for s in socks:
            threading.Thread(target=self._accept_loop, args=(s,), name="sftp-accept", daemon=True).start()
        return bound, errors

    def _accept_loop(self, s):
        while True:
            try:
                conn, peer = s.accept()
            except OSError:
                _log.debug("accept failed", exc_info=True)
                time.sleep(0.5)
                continue
            threading.Thread(target=self._serve, args=(conn, peer[0]), name="sftp-conn", daemon=True).start()

    def _admit(self, ip):
        with self._lock:
            if self._conns >= MAX_CONNECTIONS or self._unauth.get(ip, 0) >= MAX_UNAUTH_PER_ADDRESS:
                return False
            self._conns += 1
            self._unauth[ip] = self._unauth.get(ip, 0) + 1
            return True

    def _signed_in(self, ip):
        with self._lock:
            self._drop_unauth(ip)

    def _drop_unauth(self, ip):
        n = self._unauth.get(ip, 0) - 1
        if n > 0:
            self._unauth[ip] = n
        else:
            self._unauth.pop(ip, None)

    def _release(self, ip, counted_unauth):
        with self._lock:
            self._conns -= 1
            if counted_unauth:
                self._drop_unauth(ip)

    def _serve(self, sock, ip):
        ip = _plain_ip(ip)
        if not self._admit(ip):
            sock.close()
            return
        unauth = True
        try:
            if not self.panel.ask({"op": "conn", "ip": ip}).get("ok"):
                return
            unauth = self._run_transport(sock, ip)
        except Exception:  # noqa: BLE001 - one client's failure must never end the service
            _log.debug("SFTP connection ended with an error", exc_info=True)
        finally:
            try:
                sock.close()
            except OSError:
                _log.debug("socket close", exc_info=True)
            self._release(ip, unauth)

    def _run_transport(self, sock, ip):
        """Run one client's SSH connection to its end. Returns whether it never signed in."""
        t = paramiko.Transport(sock, default_window_size=WINDOW, default_max_packet_size=32768)
        conn = Connection(self, ip)
        conn.transport = t
        try:
            _restrict_algorithms(t)
            t.add_server_key(self.host_key)
            t.set_subsystem_handler("sftp", PanelSftpServer, VirtualSftp)
            t.start_server(server=conn)
            deadline = time.monotonic() + LOGIN_GRACE
            while t.is_active() and not t.is_authenticated() and time.monotonic() < deadline \
                    and conn.tries <= MAX_AUTH_TRIES:
                time.sleep(0.2)
            if not t.is_authenticated():
                self._report_failure(conn)
                return True
            self._signed_in(ip)
            while t.is_active():
                time.sleep(1)
            return False
        finally:
            t.close()

    def _report_failure(self, conn):
        """A connection that tried a credential and never signed in: one failed sign-in for the panel."""
        if conn.offered and not conn.counted:
            self.panel.ask({"op": "auth_fail", "ip": conn.ip, "username": conn.who,
                            "why": conn.last_why or "no accepted key"})

    # ── reaching a game server's files ──
    def connect(self, target):
        """A new Backend: sftp-server as the game account on the server's host. Raises Refused."""
        try:
            if target.transport == "local":
                argv = bk.local_argv(target.user, _me())
                if argv is None:
                    raise Refused(SFTP_FAILURE, "This host has no sftp-server (OpenSSH) to reach the files with.")
                return bk.from_process(argv, "local")
            return self._connect_remote(target)
        except Refused:
            raise
        except Exception as exc:  # noqa: BLE001 - a host that cannot be reached is one answer
            _log.warning("SFTP: the host of server %s could not be reached (%s)", target.sid,
                         type(exc).__name__)
            raise Refused(SFTP_FAILURE, "The server's host cannot be reached right now.") from exc

    def _connect_remote(self, target):
        from panel.db.models import RemoteServer, db
        from panel.ops.ssh_manager import _core
        from panel.ops.ssh_manager import files as _files
        app = self._app()
        shell = bk.remote_shell(target.user)
        with app.app_context():
            server = db.session.get(RemoteServer, target.remote_id)
            if server is None:
                raise Refused(SFTP_NO_SUCH_FILE, "No such file")
            if target.transport == "tailscale":
                argv = _files._ssh_download_argv(server, shell)
                if argv is None:
                    raise Refused(SFTP_FAILURE, "The server's host cannot be reached right now.")
                return bk.from_process(argv, "ssh")
            client = _core.get_connection(server, pooled=False)
        return bk.from_channel(client, shell, "remote")

    def _app(self):
        if self._db_app is None:
            from flask import Flask
            from panel.core.config import DB_PATH
            from panel.db.models import db
            from panel.ops.ssh_manager import _core
            app = Flask("panel-sftp")
            app.config.update(SQLALCHEMY_DATABASE_URI="sqlite:///%s" % DB_PATH,
                              SQLALCHEMY_TRACK_MODIFICATIONS=False,
                              SQLALCHEMY_ENGINE_OPTIONS={"connect_args": {"timeout": 15}})
            db.init_app(app)
            _core.register_pin_app(app)
            self._db_app = app
        return self._db_app


def _plain_ip(ip):
    """`ip` without an IPv4-mapped IPv6 prefix."""
    return ip[7:] if isinstance(ip, str) and ip.startswith("::ffff:") and "." in ip else ip


def _me():
    import pwd
    return pwd.getpwuid(os.getuid()).pw_name


def _restrict_algorithms(t):
    """Offer only sftp_common's algorithms (OpenSSH's defaults that paramiko has; no SHA-1, no CBC)."""
    so = t.get_security_options()
    so.ciphers = sc.offered(sc.CIPHERS, so.ciphers)
    so.digests = sc.offered(sc.MACS, so.digests)
    so.kex = sc.offered(sc.KEX, so.kex)
    so.key_types = sc.offered(sc.HOST_KEY_TYPES + sc.PUBKEY_TYPES, so.key_types)


def _watch_lifeline():
    """End this process when the panel goes: its stdin reaches end-of-file."""
    try:
        while os.read(0, 4096):
            continue
    except OSError:
        _log.debug("lifeline read failed", exc_info=True)
    _die("the panel has stopped")


def _set_parent_death_signal():
    """Ask the kernel to send SIGTERM if the panel dies first (Linux prctl PR_SET_PDEATHSIG)."""
    try:
        import ctypes
        ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGTERM)
    except (OSError, AttributeError):
        _log.debug("prctl unavailable", exc_info=True)


def main():
    """Run the service until the panel goes."""
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr,
                        format="panel-sftp: %(levelname)s %(message)s")
    _set_parent_death_signal()
    fd = int(os.environ.get(sc.IPC_FD_ENV, "-1"))
    if fd < 0:
        print("panel-sftp: started without the panel", file=sys.stderr)
        return 2
    panel = Panel(socket.socket(fileno=fd))
    threading.Thread(target=_watch_lifeline, name="sftp-lifeline", daemon=True).start()
    cfg = panel.ask({"op": "hello", "pid": os.getpid()})
    if not cfg.get("ok"):
        return 3
    service = Service(panel, cfg)
    try:
        bound, errors = service.listen()
    except OSError as exc:
        panel.ask({"op": "ready", "bound": [], "error": str(exc)})
        return 4
    panel.ask({"op": "ready", "bound": bound, "error": "; ".join(errors)})
    signal.signal(signal.SIGTERM, lambda *_a: _die("asked to stop"))
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    sys.exit(main())
