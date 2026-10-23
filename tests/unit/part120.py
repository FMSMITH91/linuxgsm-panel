"""Part 120 of the unit suite: the twenty-first review's ssh_manager and file browser fixes (builder B).

* An SSH port move whose own revert RAISED part-way (paramiko, after the drop-in was put back) had
  the undo-on-raise wrapper run the restore verb a second time. That verb is not idempotent: with
  its snapshot already moved back it DELETES the drop-in, so sshd fell back to sshd_config's port
  alone — the port the panel dials stopped answering. Each part of the revert now runs once.
* A raise in step 1's own re-read, after the new port's allow went in, is undone too.
* The Public SSH card's Limit / Allow act only on the ports public SSH is open on now (plus the port
  the panel dials): a port the operator closed after the panel's move, as the move advises, stays
  closed (Limit re-opened it to the internet).
* The editor's save and an upload refuse a FILE at a folder the console's log goes in, resolved,
  in every state (`log`, or `disk/logs` while `log -> disk/logs` dangles), as create and rename do.

HOW IT RUNS. On part12's stand-ins with its transport tripwire armed for the part: run_privileged
answers from a small stand-in host (a drop-in and its snapshot, a ufw rule table). The file
browser's host-side commands run under bash over this part's own fixture home. Nothing reaches a
host, sudo, tmux or the checkout's data/.
"""
import os
import shutil as _shutil120
import subprocess as _sp120  # nosec B404 - bash over this part's own fixture home, fixed argv
import tempfile as _tf120
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part12 import _P9_TRIPPED, _p9_arm, _p9_core, _p9_patch, _p9_restore_all
from unit.part114 import _PUB_ADDR114, _TS_ADDR114
from panel.ops.ssh_manager import files as _f120
from panel.ops.ssh_manager import hosts as _hosts120
from panel.security import privileged as _priv120

_TRIP120_START = len(_P9_TRIPPED)
_TMP120 = _tf120.mkdtemp(prefix="lgsm-unit-p120-")
# Stand-in addresses, never dialled (every transport is stubbed and the tripwire is armed): part114's.
_PUB_ADDR120, _TS_ADDR120 = _PUB_ADDR114, _TS_ADDR114
_HDR120 = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n"


def _row120(port=22, host=_PUB_ADDR120, auth="key"):
    return NS(id=-120, name="p120", host=host, port=port, auth_method=auth, is_local=False)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. An SSH port move's revert that raises part-way: every part of the undo runs once
# ════════════════════════════════════════════════════════════════════════════════════════════════
class _Box120:
    """A stand-in host for change_ssh_port: its drop-in and snapshot, and what each verb did.

    `blow` names (verb, nth call) pairs that raise AFTER doing their work, as paramiko does when
    the channel drops while the answer is read (its ConnectionError is marked command_started);
    `unsent` names pairs that raise BEFORE, as a session that could not be opened does.
    """

    def __init__(self, socket=False, blow=(), inactive=False, unsent=(), dropin="OLD"):
        self.dropin, self.bak, self.socket, self.inactive = dropin, None, socket, inactive
        self.blow, self.calls, self.sent, self.added = set(blow), {}, [], False
        self.unsent = set(unsent)

    def _tick(self, verb):
        self.calls[verb] = self.calls.get(verb, 0) + 1
        self.sent.append(verb)
        if (verb, self.calls[verb]) in self.blow:
            e = ConnectionError("Command failed: socket closed")
            e.command_started = True
            raise e

    def priv(self, server, verb, args=(), **kw):
        if (verb, self.calls.get(verb, 0) + 1) in self.unsent:
            self.calls[verb] = self.calls.get(verb, 0) + 1
            e = ConnectionError("Command failed: no session")
            e.command_started = False
            raise e
        if verb in ("sshd-backup-dropin", "sshd-socket-backup"):
            self.bak = self.dropin
        elif verb in ("sshd-restore-dropin", "sshd-socket-restore"):
            # The verb's own body (privileged._r35j_restore_sh): the snapshot is copied back and KEPT, or
            # with no snapshot the drop-in is removed. (It moved the snapshot back until review 1022b.)
            self.dropin = self.bak
        elif verb == "ufw-allow-proto-port":
            self.added = True
        elif verb == "ufw-delete-allow-proto-port":
            self.added = False
        self._tick(verb)
        return self._answer(verb)

    def _answer(self, verb):
        if verb in ("sshd-backup-dropin", "sshd-socket-backup"):
            # What the real verb prints answering 0: whether there was a drop-in to copy (review 1022c).
            return (_priv120.R36B_SNAP_COPIED if self.bak is not None else _priv120.R36B_SNAP_NONE), "", 0
        if verb == "ufw-status":
            if self.inactive:
                return "Status: inactive\n", "", 0
            return _HDR120 + "22/tcp                     LIMIT IN    Anywhere\n" + (
                "2022/tcp                   ALLOW IN    Anywhere\n" if self.added else ""), "", 0
        if verb == "ufw-show-added":
            return ("Added user rules (see 'ufw status' for running firewall):\nufw limit 22/tcp\n"
                    + ("ufw allow 2022/tcp\n" if self.added else "")), "", 0
        if verb == "listening-sockets":      # sshd never comes up on 2022: the move reverts
            return "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n", "", 0
        if verb == "sshd-effective-config":
            return "port 22\n", "", 0
        return "", "", 0

    def write(self, server, path, content, **kw):
        self._tick("write")
        self.dropin = content
        return "", "", 0

    def restart(self, server, socket_mode=False):
        self._tick("restart")
        return "", "", 0            # _restart_ssh_listener's answer: the undo reads it (review 1022c)


def _move120(box):
    """(raised, the drop-in, restores, restarts, allow left, closes, daemon-reloads) of a 22 -> 2022 move."""
    _p9_patch(_p9_core, "run_privileged", box.priv)
    _p9_patch(_p9_core, "run_command", lambda *a, **k: ("", "", 1))
    _p9_patch(_p9_core, "write_root_file", box.write)
    _p9_patch(_hosts120, "_sshd_socket_activated", lambda s, _b=box: _b.socket)
    _p9_patch(_hosts120, "_restart_ssh_listener", box.restart)
    try:
        _hosts120.change_ssh_port(_row120(), 2022)
        raised = False
    except ConnectionError:
        raised = True
    restore = box.calls.get("sshd-socket-restore" if box.socket else "sshd-restore-dropin", 0)
    return (raised, box.dropin, restore, box.calls.get("restart", 0), box.added,
            box.calls.get("ufw-delete-allow-proto-port", 0), box.calls.get("systemd-daemon-reload", 0))


def _undo_once120():
    got = {
        # _revert put the drop-in back, then its own restart raised
        "restart raises": _move120(_Box120(blow={("restart", 2)})),
        # the restore itself ran and then the channel dropped
        "restore raises": _move120(_Box120(blow={("sshd-restore-dropin", 1)})),
        # socket-activated: _revert's daemon-reload raised after the restore
        "reload raises": _move120(_Box120(socket=True, blow={("systemd-daemon-reload", 2)})),
        # the restore never reached the host (no session): still owed, so the wrapper's retry restores
        "restore unsent": _move120(_Box120(unsent={("sshd-restore-dropin", 1)})),
        # control: a revert that raises nothing still restores once and restarts once more
        "no raise": _move120(_Box120()),
    }
    check("ssh port move: a revert that RAISES after putting the drop-in back (its restart or its daemon-reload) "
          "leaves the prior drop-in in place: the restore verb runs ONCE (run again, it "
          "deleted the drop-in it had just restored, and sshd fell back to sshd_config's port alone)",
          [got[k][1:3] for k in ("restart raises", "reload raises")] == [("OLD", 1)] * 2,
          repr(got))
    check("ssh port move: ...and still raises, with the rest owed done ONCE: the new port's allow closed, the "
          "socket unit re-read and the listener restarted onto the restored config; a restore that never "
          "reached the host is still retried (control: a revert that raises nothing is unchanged)",
          got == {"restart raises": (True, "OLD", 1, 3, False, 1, 0),
                  # Since review 1022c a restore whose answer was lost is run once more at once (the verb
                  # copies and keeps the snapshot, so that puts back the same file): confirmed, the revert
                  # goes on and answers instead of raising (part129 has the unconfirmed side).
                  "restore raises": (False, "OLD", 2, 2, False, 1, 0),
                  "reload raises": (True, "OLD", 1, 2, False, 1, 3),
                  "restore unsent": (True, "OLD", 2, 2, False, 1, 0),
                  "no raise": (False, "OLD", 1, 2, False, 1, 0)},
          repr(got))


def _step1_raise120():
    got = {}
    for case, box in (("active re-read raises", _Box120(blow={("ufw-status", 2)})),
                      ("inactive re-read raises", _Box120(inactive=True, blow={("ufw-show-added", 2)}))):
        raised, left = _move120(box)[0::4]
        got[case] = (raised, left, "sshd-backup-dropin" in box.sent)
    check("ssh port move: a transport that raises in step 1's own re-read, after the new port's allow went in, "
          "removes that allow before the error goes on (it stayed: a public allow for a port nothing serves), on "
          "an active firewall and an inactive one",
          got == {"active re-read raises": (True, False, False), "inactive re-read raises": (True, False, False)},
          repr(got))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. Public SSH Limit / Allow never re-open a port the operator closed
# ════════════════════════════════════════════════════════════════════════════════════════════════
class _Ufw120:
    """A ufw rule table behind the public-SSH verbs: rules are (to, action, v6), every source public."""

    def __init__(self, *rules, sshd="port 2222\nport 22\n"):
        self.rules, self.sshd, self.ran = [list(r) for r in rules], sshd, []

    def status(self):
        rows = ("%-26s %-11s %s\n" % (t + (" (v6)" if v6 else ""), a, "Anywhere (v6)" if v6 else "Anywhere")
                for t, a, v6 in self.rules)
        return _HDR120 + "".join(rows)

    def _put(self, to, action):
        for v6 in (False, True):
            hit = [r for r in self.rules if r[0] == to and r[2] == v6]
            if hit:
                hit[0][1] = action
            else:
                self.rules.append([to, action, v6])

    def __call__(self, server, verb, args=(), **kw):
        if verb == "ufw-status":
            return self.status(), "", 0
        if verb == "sshd-effective-config":
            return self.sshd, "", 0
        self.ran.append((verb, list(args)))
        if verb in ("ufw-allow-port", "ufw-limit-port"):
            self._put(args[0], "ALLOW IN" if verb == "ufw-allow-port" else "LIMIT IN")
        elif verb in ("ufw-delete-allow-port", "ufw-delete-limit-port"):
            gone = "ALLOW IN" if verb == "ufw-delete-allow-port" else "LIMIT IN"
            self.rules = [r for r in self.rules if not (r[0] == args[0] and r[1] == gone)]
        return "", "", 0

    def left(self):
        return sorted((t, a) for t, a, v6 in self.rules if not v6)


def _limit120(rules, mode, row):
    ufw = _Ufw120(*rules)
    _p9_patch(_p9_core, "run_privileged", ufw)
    _p9_patch(_p9_core, "run_command", lambda *a, **k: ("", "", 1))
    ok, msg = _hosts120.remote_set_public_ssh(row, mode)
    return ok, ufw.left(), str(msg)


def _both120(to, action):
    return [(to, action, False), (to, action, True)]


def _public_open120():
    got = {
        # moved 22 -> 2222 (sshd keeps 22 as the fallback), then 22/tcp closed as the move advised
        "22 closed, limit": _limit120(_both120("2222/tcp", "ALLOW IN"), "limit", _row120(port=2222)),
        "22 closed, allow": _limit120(_both120("2222/tcp", "LIMIT IN"), "allow", _row120(port=2222)),
        # control: 22 still open, so Limit covers it too
        "22 open, limit": _limit120(_both120("2222/tcp", "ALLOW IN") + _both120("22/tcp", "ALLOW IN"), "limit",
                                    _row120(port=2222)),
        # control: everything off on a Tailscale-SSH row (no dial port): sshd's first port only
        "all off, limit": _limit120([], "limit", _row120(host=_TS_ADDR120, auth="tailscale")),
        # control: the dial port is acted on even with no rule of its own
        "dial port closed": _limit120(_both120("22/tcp", "ALLOW IN"), "limit", _row120(port=2222)),
    }
    check("public SSH Limit / Allow: a port sshd still listens on but the operator closed (22 after the panel's "
          "move to 2222) stays closed; only 2222 is rate-limited / opened (Limit put 22/tcp back, public again)",
          got["22 closed, limit"] == (True, [("2222/tcp", "LIMIT IN")], "Public SSH is now rate-limited (port 2222)")
          and got["22 closed, allow"][:2] == (True, [("2222/tcp", "ALLOW IN")]), repr(got))
    check("public SSH Limit: ...while every port that IS open, and the port the panel dials, are still acted on, "
          "and with public SSH off everywhere only sshd's first port opens (controls)",
          got["22 open, limit"][:2] == (True, [("22/tcp", "LIMIT IN"), ("2222/tcp", "LIMIT IN")])
          and got["all off, limit"][:2] == (True, [("2222/tcp", "LIMIT IN")])
          and got["dial port closed"][:2] == (True, [("22/tcp", "LIMIT IN"), ("2222/tcp", "LIMIT IN")]),
          repr(got))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. Save and upload never put a FILE where the console's log folders go
# ════════════════════════════════════════════════════════════════════════════════════════════════
_HOME120 = os.path.join(_TMP120, "home", "p120u")
_SELF120 = "p120srv"


def _home_tree120(link=True):
    """A stopped server's home: `log -> disk/logs` (dangling) when `link`, else no `log` at all."""
    _shutil120.rmtree(os.path.join(_TMP120, "home"), ignore_errors=True)
    os.makedirs(os.path.join(_HOME120, "disk"))
    if link:
        os.symlink("disk/logs", os.path.join(_HOME120, "log"))


def _shell120(server, user, cmd, timeout=30, selfname=None):
    """shell_as_game_user over the fixture home: the command's /home/p120u is the temp tree's."""
    r = _sp120.run(["/bin/bash", "-c", cmd.replace("/home/p120u", _HOME120)],  # nosec B603 - own text
                   capture_output=True, text=True, timeout=30,
                   env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8"})
    return r.stdout, r.stderr, r.returncode


def _write_cases120():
    """(case, link?, call, the path it would make) for _console_writes120."""
    big = "x" * 90000          # past the one-shot size: the chunked path
    console = "log/console/%s-console.log" % _SELF120
    return (
        ("save log", True, lambda: _f120.write_file(None, "p120u", "log", "t", _SELF120), "disk/logs"),
        ("save disk/logs big", True, lambda: _f120.write_file(None, "p120u", "disk/logs", big, _SELF120),
         "disk/logs"),
        ("upload logs", True, lambda: _f120.upload_file(None, "p120u", "disk", "logs", b"t", True, _SELF120),
         "disk/logs"),
        ("save log, no link", False, lambda: _f120.write_file(None, "p120u", "log", "t", _SELF120), "log"),
        ("upload console", False,
         lambda: _f120.upload_file(None, "p120u", "log", "console", b"t", True, _SELF120), "log/console"),
        ("save elsewhere", True, lambda: _f120.write_file(None, "p120u", "disk/other", "t", _SELF120),
         "disk/other"),
        ("save console log", False, lambda: _f120.write_file(None, "p120u", console, "t", _SELF120), console))


def _console_writes120():
    _p9_patch(_p9_core, "shell_as_game_user", _shell120)
    got = {}
    for case, link, call, made in _write_cases120():
        _home_tree120(link)
        ok, msg = call()
        got[case] = (ok, msg, os.path.lexists(os.path.join(_HOME120, made)))
    ref = (False, _f120.R34B_WRITE_RESERVED, False)
    check("files: on a stopped server, a save or an upload of a FILE where the console's log folders go (`log` through "
          "its dangling link, `disk/logs` itself one-shot and chunked, `log` and `log/console` with no `log` at all) "
          "is refused and makes nothing (it stopped LinuxGSM making its log folders on the next start)",
          [got[k] for k in ("save log", "save disk/logs big", "upload logs", "save log, no link", "upload console")]
          == [ref] * 5, repr(got))
    check("files: ...while a file off that path, and the console's log file itself on a stopped server, are still "
          "written (controls), and the refusal is one of the fixed write reasons an audit row may carry",
          got["save elsewhere"][0::2] == (True, True) and got["save console log"][0::2] == (True, True)
          and _f120.write_failure_reason(_f120.R34B_WRITE_RESERVED) == _f120.R34B_WRITE_RESERVED, repr(got))


# ════════════════════════════════════════════════════════════════════════════════════════════════
try:
    _p9_arm(who="part120")
    for _fn120 in (_undo_once120, _step1_raise120, _public_open120, _console_writes120):
        _fn120()
        _p9_restore_all()
        _p9_arm(who="part120")
finally:
    _p9_restore_all()
    _shutil120.rmtree(_TMP120, ignore_errors=True)

check("part120: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP120_START, repr(_P9_TRIPPED[_TRIP120_START:][:6]))
