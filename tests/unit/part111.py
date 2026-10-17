"""Part 111 of the unit suite: the nineteenth review's ssh_manager fixes (review 1017b, builder B).

* The file browser's Delete refuses the live console's log, `log/console` and `log` — by their text
  before the host is asked, and on the host by their RESOLVED path (a `log -> disk/logs` home, then
  deleting `disk`). tmux pipe-pane goes on appending to the inode it opened, so a deleted log left
  the console reading a path nothing wrote to until the next start, and freed no space, under
  "Deleted". Write, upload, rename and create already refused it; delete was the one left out.
* Rename refuses a NEW name the console reads (a file renamed to `log`), as create refuses it.

HOW IT RUNS. As part60 does: on part12's Flask app and client helpers, part12's transport tripwire
re-armed for this part's duration, every stub undone in its finally. The host side runs in a REAL
bash over a throwaway home. The console is a stand-in for LinuxGSM's pipe-pane — the same
`exec cat >> <log>` it runs, fed on its stdin — and is read with the panel's own console poll
command, so "the console keeps receiving lines" is measured, not assumed. Nothing reaches a host,
sudo, tmux or the checkout's data/.
"""
import json
import os
import pwd as _pwd111
import shutil as _shutil111
import subprocess as _sp111  # nosec B404 - runs bash on this part's own commands and a cat writer
import tempfile as _tf111
import sys as _sys111
import time as _time111
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part05 import _helper as _helper111
from unit.part12 import (_P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_core, _p9_json, _p9_ms, _p9_patch,
                         _p9_restore_all, _p9_sf, _p9_so, _p9_trip)
from panel.db.models import AuditLog, GameServer, RemoteServer, User, db
from panel.ops.ssh_manager import files as _files111
from panel.ops.ssh_manager import game as _game111
from panel.ops.ssh_manager import hosts as _hosts111
from panel.security import privileged as _priv111
from panel.services.bots import discord as _dc111
from panel.routes import _shared as _sh111
from panel.routes import server_files as _sf111
from panel.security import auth as _auth111

_TRIP111_START = len(_P9_TRIPPED)
_ROOT111 = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_USER111 = "cr111"
_HOME111 = os.path.realpath(_tf111.mkdtemp(prefix="lgsm-unit-p111-home-"))
_SHELLS111 = []
_mine111 = {"hosts": [], "servers": [], "users": []}
_DEL111 = "/api/server/%d/delete-path"
_LOG111 = "log/console/csgoserver-console.log"
_WRITERS111 = []
_PRELUDE111 = {"text": ""}            # bash run before a command: a stand-in for one host behaviour


# ── fixtures ────────────────────────────────────────────────────────────────────────────────────
def _bash111(server, user, sh, timeout=30, selfname=None):
    """shell_as_game_user, in a real bash, with /home/<account> pointing at the throwaway home."""
    _SHELLS111.append(sh)
    script = _PRELUDE111["text"] + sh.replace("/home/" + _USER111, _HOME111)
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
    p = _sp111.run(["bash", "-c", script],  # nosec B603 B607
                   capture_output=True, text=True, timeout=30, check=False,
                   env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C.UTF-8"})
    return p.stdout, p.stderr, p.returncode


def _no_privileged111(remote, users):
    """privileged_accounts as a host would answer it for a plain game account: nobody is."""
    return {}


def _clear111():
    for name in os.listdir(_HOME111):
        p = os.path.join(_HOME111, name)
        if os.path.islink(p) or not os.path.isdir(p):
            os.unlink(p)
        else:
            _shutil111.rmtree(p)


def _console111(logdir="log"):
    """A fresh home whose console log (under `logdir`) is held open by a pipe-pane stand-in.

    -> (writer, log path). The writer is LinuxGSM's own pipe-pane command, `exec cat >> <log>`:
    it opens the file once and appends to that inode, whatever later happens to the name.
    """
    _stop_writers111()
    _clear111()
    del _SHELLS111[:]
    os.makedirs(os.path.join(_HOME111, logdir, "console"))
    os.makedirs(os.path.join(_HOME111, logdir, "script"))
    with open(os.path.join(_HOME111, logdir, "script", "old.log"), "w", encoding="utf-8") as fh:
        fh.write("old\n")
    if logdir != "log":
        os.symlink(logdir, os.path.join(_HOME111, "log"))
    path = os.path.join(_HOME111, _LOG111)
    # Made first, as LinuxGSM's start touches it, and held open for reading: `>>` appends to this
    # same inode, and the handle goes on reading it after a delete — which a read of the writer's
    # /proc fd did not do safely (before bash's `exec` it is the SUITE's stdout pipe, and reading
    # that blocks the run for good).
    with open(path, "w", encoding="utf-8"):
        pass
    rd = open(path, "rb")  # noqa: SIM115 - closed with the writer in _stop_writers111
    # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
    w = _sp111.Popen(["bash", "-c", 'exec cat >> "$1"', "p111", path],  # nosec B603 B607
                     stdin=_sp111.PIPE, stdout=_sp111.DEVNULL, stderr=_sp111.DEVNULL)
    w.p111_rd = rd
    _WRITERS111.append(w)
    return w, path


def _say111(w, line):
    """One console line, as the game would print it, and wait (bounded) until the writer appended it."""
    w.stdin.write((line + "\n").encode())
    w.stdin.flush()
    want = (line + "\n").encode()
    for _ in range(300):
        w.p111_rd.seek(0)
        if want in w.p111_rd.read():
            return
        _time111.sleep(0.01)


def _stop_writers111():
    for w in _WRITERS111:
        w.p111_rd.close()
        try:
            w.stdin.close()
        except OSError:  # nosec B110 - already closed is what stopping means here
            pass
        try:
            w.wait(timeout=5)
        except Exception:  # noqa: BLE001 - eventlet's green wait raises its own TimeoutExpired class
            w.kill()
            w.wait()
    del _WRITERS111[:]


def _poll111(ino=0, pos=0):
    """The panel's console poll, run over the throwaway home: (head line, framed bytes)."""
    cmd = _sf111._console_poll_cmd("/home/%s/%s" % (_USER111, _LOG111), ino, pos)
    out, _e, _rc = _bash111(None, _USER111, cmd)
    head, _nl, framed = (out or "").partition("\n")
    return head, framed


def _seen111(line):
    """Whether the console's poll, from the start of the log, reads `line` now."""
    head, framed = _poll111()
    return head != "MISSING" and line in framed


def _host111():
    with _p9.app_context():
        r = RemoteServer(name="p111-host", host="p111-host.example", port=22, username="admin",
                         auth_method="key", auth_credential="", is_online=True)
        db.session.add(r)
        db.session.commit()
        _mine111["hosts"].append(r.id)
        gs = GameServer(remote_id=r.id, name="p111-" + _USER111, short_name=_USER111, game_type="csgo",
                        port=27611, installed=True, status="online")
        db.session.add(gs)
        db.session.commit()
        _mine111["servers"].append(gs.id)
        admin = User(username="p111_admin", password_hash=_auth111.hash_password("Str0ng!passw0rd-p111"),
                     display_name="p111 admin", is_superadmin=True, is_active=True)
        db.session.add(admin)
        db.session.commit()
        _mine111["users"].append(admin.id)
        return gs.id, admin.id


def _delete111(client, sid, rel):
    try:
        r = client.post(_DEL111 % sid, json={"path": rel})
    except Exception as exc:  # noqa: BLE001 - a crash fails the check that made it, not the part
        return None, {"raised": repr(exc)[:200]}
    return r.status_code, _p9_json(r)


def _last_delete_row111():
    with _p9.app_context():
        a = (AuditLog.query.filter(AuditLog.action == "delete_file").order_by(AuditLog.id.desc()).first())
        return None if a is None else NS(detail=a.detail or "", success=a.success)


# ── delete: the console's paths by name ─────────────────────────────────────────────────────────
def _by_name111(client, sid):
    """The log, its folder and `log` are refused by their text, nothing is sent, the console goes on."""
    w, path = _console111()
    _say111(w, "p111 line one")
    cases = (_LOG111, "log/console", "log", "./log/", "log/console/", "cfg/../log")
    got = [(rel, _delete111(client, sid, rel)) for rel in cases]
    want = (200, {"success": False, "message": _files111.DELETE_CONSOLE})
    bad = [(rel, r) for rel, r in got if r != want]
    check("delete route: the console's log, log/console and log (however written) are refused "
          "with the console reason, and nothing is sent to the host",
          not bad and not _SHELLS111, repr((bad[:3], _SHELLS111[:1])))
    row = _last_delete_row111()
    check("delete route: ...the refusal is audited, failed, with the console reason in the row",
          row is not None and row.success is False and _files111.DELETE_CONSOLE in row.detail,
          repr(row))
    _say111(w, "p111 line two")
    check("delete route: ...the log is still there and the console's own poll reads a line the "
          "game printed AFTER the refused deletes",
          os.path.isfile(path) and _seen111("p111 line two"), repr(_poll111()))
    code, body = _delete111(client, sid, "log/script/old.log")
    check("delete route (real bash): another log beside the console's is deleted (control)",
          (code, body.get("success")) == (200, True)
          and not os.path.exists(os.path.join(_HOME111, "log/script/old.log")), repr((code, body)))
    code, body = _delete111(client, sid, "log/script")
    _say111(w, "p111 line three")
    check("delete route (real bash): ...so is log/script, and the console still reads new lines",
          (code, body.get("success")) == (200, True) and _seen111("p111 line three"), repr((code, body)))


# ── delete: the console's paths resolved on the host ────────────────────────────────────────────
def _resolved111(client, sid):
    """With `log -> disk/logs`, deleting disk or disk/logs is refused ON THE HOST."""
    w, path = _console111("disk/logs")
    _say111(w, "p111 linked one")
    got = [(rel, _delete111(client, sid, rel)) for rel in ("disk", "disk/logs", "disk/logs/console")]
    want = (200, {"success": False, "message": _files111.DELETE_CONSOLE})
    bad = [(rel, r) for rel, r in got if r != want]
    check("delete route (real bash): with log -> disk/logs, deleting disk, disk/logs or "
          "disk/logs/console is refused on the host with the console reason",
          not bad and len(_SHELLS111) == 3, repr((bad[:3], len(_SHELLS111))))
    _say111(w, "p111 linked two")
    check("delete route (real bash): ...the log is still there and the console reads a line "
          "printed after them", os.path.isfile(path) and _seen111("p111 linked two"), repr(_poll111()))
    code, body = _delete111(client, sid, "disk/logs/script")
    check("delete route (real bash): ...a folder beside the console's is deleted (control)",
          (code, body.get("success")) == (200, True)
          and not os.path.exists(os.path.join(_HOME111, "disk/logs/script")), repr((code, body)))


# ── what the refusal prevents, measured ─────────────────────────────────────────────────────────
def _old_delete_silences111():
    """The command delete_path ran before: the console's poll goes MISSING while the game prints on."""
    w, path = _console111()
    _say111(w, "p111 before")
    seen_before = _seen111("p111 before")
    # The pre-fix inner command, run as it was: _protected_resolved, then `rm -rf -- "$t"`.
    ap = "/home/%s/%s" % (_USER111, _LOG111)
    old = _files111._protected_resolved(_USER111, ap, "csgoserver", 'rm -rf -- "$t" && echo __OK__')
    out, _e, rc = _bash111(None, _USER111, old)
    _say111(w, "p111 after")
    head, _f = _poll111()
    check("console (stand-in pipe-pane): the old unguarded delete said OK, and from then on the "
          "console's poll answers MISSING although the game goes on printing — what the refusal "
          "prevents", seen_before and rc == 0 and "__OK__" in out and head == "MISSING"
          and not os.path.exists(path), repr((seen_before, rc, out, head)))


# ── rename's new name, and the catalogs ─────────────────────────────────────────────────────────
def _rename_dest111():
    """A new name the console reads is refused before the host is asked, as create refuses it."""
    reserved = "That name is reserved for LinuxGSM or the game's account — choose another."
    got = [_files111.rename_refusal(_USER111, rel, new, "csgoserver")
           for rel, new in (("notes.txt", "log"), ("log/x", "console"),
                            ("log/console/old.log", "csgoserver-console.log"))]
    ok = _files111.rename_refusal(_USER111, "log/console/old.log", "older.log", "csgoserver")
    check("rename: a file renamed to log, log/console or the console's log is refused (reserved); "
          "an ordinary name beside them is not (control)",
          got == [reserved] * 3 and ok is None, repr((got, ok)))


def _catalog111():
    keys = {}
    for lg in ("es", "fr"):
        keys[lg] = set()
        root = os.path.join(_ROOT111, "translations", lg)
        for name in sorted(os.listdir(root)):
            if name.endswith(".json"):
                with open(os.path.join(root, name), encoding="utf-8") as fh:
                    keys[lg] |= set(json.load(fh))
    check("delete: the console refusal is in the Spanish and French catalogs, and delete's audit "
          "reason accepts it",
          all(_files111.DELETE_CONSOLE in k for k in keys.values())
          and _files111.delete_failure_reason(_files111.DELETE_CONSOLE) == _files111.DELETE_CONSOLE,
          repr({lg: _files111.DELETE_CONSOLE in k for lg, k in keys.items()}))


# ── the OS update: "watching it" only for the panel's own job ──────────────────────────────────
_OWN_PROCS111 = (
    ("the helper's job unit", [_priv111.HELPER_PATH, "--job", "os-update-run"], True),
    ("the helper's forked job", [_priv111.HELPER_PATH, "os-update-run"], True),
    ("the shell form's script", ["bash", "-c", "x; echo \"=== OS update started $(date) ===\""], True),
    ("an operator's apt-get upgrade", ["apt-get", "upgrade"], False),
    ("an operator's apt-get -y full-upgrade", ["apt-get", "-y", "full-upgrade"], False),
    ("the helper answering this very probe", [_priv111.HELPER_PATH, "os-update-own-running"], False),
)


def _own_seen111():
    """(stand-in pids, what the verb's pgrep named, the remote form's own shell pid, what it named)."""
    argv = _priv111.tool_argv("os-update-own-running", [])
    procs = []
    try:
        for _what, words, _want in _OWN_PROCS111:
            procs.append(_sp111.Popen(  # nosec B603 - a sleeping stand-in; its words are only argv
                [_sys111.executable, "-c", "import time; time.sleep(60)"] + words,
                stdout=_sp111.DEVNULL, stderr=_sp111.DEVNULL))
        r = _sp111.run(argv, capture_output=True, text=True, timeout=20, check=False)  # nosec B603
        seen = _pids111(r.stdout)
        # The rendered remote form, as a remote's sudo runs it: a bash -c whose own line holds the pattern.
        r = _sp111.run(["bash", "-c", "echo $$; %s; true" % _priv111.remote_command(  # nosec B603 B607
            "os-update-own-running", [], merge_stderr=False)], capture_output=True, text=True, timeout=20)
        own = _pids111(r.stdout, keep_order=True) or [0]
    finally:
        for pr in procs:
            pr.kill()
            pr.wait()
    return [pr.pid for pr in procs], seen, own[0], set(own[1:])


def _pids111(text, keep_order=False):
    pids = [int(x) for x in text.split() if x.isdigit()]
    return pids if keep_order else set(pids)


def _own_pgrep111():
    """os-update-own-running through the real pgrep, against sleeping stand-ins named as each process."""
    argv = _priv111.tool_argv("os-update-own-running", [])
    check("os-update-own-running: the helper's table builds the panel's argv (held equal)",
          _helper111.VERBS["os-update-own-running"][1]([]) == argv, repr(argv))
    pids, seen, shell, remote_seen = _own_seen111()
    want = [(w, x) for w, _a, x in _OWN_PROCS111]
    got = [(w, pid in seen) for (w, _a, _x), pid in zip(_OWN_PROCS111, pids)]
    remote = [(w, pid in remote_seen) for (w, _a, _x), pid in zip(_OWN_PROCS111, pids)]
    check("os-update-own-running (real pgrep): the panel's own job (helper unit, forked job, shell form) "
          "reads as running; an operator's apt-get upgrade and the probe itself do not",
          got == want, repr([g for g, w in zip(got, want) if g != w]))
    check("os-update-own-running: ...the remote's rendered form finds the same, and never its own shell",
          remote == want and shell not in remote_seen, repr((shell, sorted(remote_seen))))


def _start_answers111():
    """remote_os_update_start and system_ops.os_run_update, for each answer of the two probes."""
    started = (_priv111.OS_UPDATE_STARTED, "", 0)
    cases = (("idle", {"apt-upgrade-running": 1}, True),
             ("own job", {"apt-upgrade-running": 0, "os-update-own-running": 0}, False),
             ("foreign apt", {"apt-upgrade-running": 0, "os-update-own-running": 1}, False),
             ("own probe unread", {"apt-upgrade-running": 0, "os-update-own-running": -1}, False),
             ("upgrade probe unread", {"apt-upgrade-running": -1}, False))
    want = {"idle": None, "own job": (True, "An update is already running — watching it."),
            "foreign apt": (False, _p9_so.R31B_UPDATE_BUSY),
            "own probe unread": (False, _p9_so.R31B_UPDATE_UNCHECKED),
            "upgrade probe unread": (False, _p9_so.R31B_UPDATE_UNCHECKED)}
    bad = []
    for name, rcs, may_start in cases:
        calls = []

        def _rp(server, verb, args=(), _r=rcs, _c=calls, **k):
            _c.append(verb)
            return started if verb == "os-update-run" else ("", "", _r.get(verb, 97))

        def _rv(verb, args=(), _r=rcs, _c=calls, **k):
            _c.append(verb)
            return started if verb == "os-update-run" else ("", "", _r.get(verb, 97))
        _p9_patch(_p9_core, "run_privileged", _rp)
        remote = _hosts111.remote_os_update_start(NS(id=None, is_local=False, host="p111.example.invalid"))
        remote_started = "os-update-run" in calls
        del calls[:]
        _p9_patch(_p9_so, "_run_verb", _rv)
        _p9_patch(_p9_so, "_can_escalate", lambda: True)
        local = _p9_so.os_run_update()
        local_started = "os-update-run" in calls
        w = want[name]
        if (remote_started, local_started) != (may_start, may_start) \
                or (w is not None and (remote, local) != (w, w)):
            bad.append((name, remote, local, remote_started, local_started))
    check("os update start: watched only when the PANEL's job is the one running; an apt-get upgrade the "
          "panel did not start, or a probe that did not answer, is refused with a true reason and nothing "
          "is started over it (remote and panel host)", not bad, repr(bad))


def _status_stale111():
    """A previous run's sentinel, read while the panel's new job is starting, is not this run's end."""
    done_log = "=== OS update started ===\nold run\n%s0\n" % _priv111.OS_UPDATE_DONE
    got = {}
    for name, own in (("starting", 0), ("finished", 1), ("unread", -1)):
        _p9_patch(_p9_core, "run_privileged", lambda server, verb, args=(), _o=own, **k: (
            (done_log, "", 0) if verb == "os-update-log" else ("", "", _o)))
        st = _hosts111.remote_os_update_status(NS(id=None, is_local=False, host="p111.example.invalid"))
        got[name] = (st.get("done"), st.get("running"), st.get("log"))
    check("os update status: a sentinel read while the panel's own job runs is the previous run's — not "
          "done, no old log; with the job gone it is done (control)",
          got["starting"] == (False, True, "") and got["finished"][0] is True
          and got["unread"][0] is True and "old run" in got["finished"][2], repr(got))


# ── LinuxGSM config and file reads: a file that is there and unreadable is not an empty file ────
_CFGDIR111 = "lgsm/config-lgsm/csgoserver"


def _cfg_home111():
    _stop_writers111()
    _clear111()
    del _SHELLS111[:]
    _PRELUDE111["text"] = ""
    for name, text in (("_default.cfg", 'maxplayers="16"\n'), ("common.cfg", 'defaultmap="de_dust2"\n'),
                       ("csgoserver.cfg", 'port="27015"\nservername="kept"\n')):
        path = os.path.join(_HOME111, _CFGDIR111, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    return os.path.join(_HOME111, _CFGDIR111, "csgoserver.cfg")


def _cfg_reads111():
    """base64 failing on a file that is there (the account cannot read it) never reads as empty."""
    fail_inst = ('base64() { case "$1" in *csgoserver.cfg) echo "base64: Permission denied" >&2; return 1 ;; '
                 '*) command base64 "$@" ;; esac; }; ')
    inst = _cfg_home111()
    ok = _files111.lgsm_read_config(None, _USER111, "csgoserver")
    _PRELUDE111["text"] = fail_inst
    bad = _files111.lgsm_read_config(None, _USER111, "csgoserver")
    check("lgsm_read_config: an instance cfg that is there and cannot be read is an error saying so, never "
          "an empty Raw editor (whose Save wrote '' over it); a readable one reads (control)",
          ok.get("raw") == 'port="27015"\nservername="kept"\n' and not ok.get("error")
          and bad.get("error") == _files111.R31B_CFG_UNREADABLE and bad.get("raw") == "", repr((ok, bad)))
    w_ok, w_msg = _files111.lgsm_write_config(None, _USER111, "csgoserver", {"maxplayers": "20"})
    with open(inst, encoding="utf-8") as fh:
        after = fh.read()
    check("lgsm_write_config: ...and a settings save refuses rather than writing the updates alone over it",
          w_ok is False and after == 'port="27015"\nservername="kept"\n', repr((w_ok, w_msg, after)))
    _PRELUDE111["text"] = ('base64() { case "$1" in *secrets-csgoserver.cfg) return 1 ;; '
                           '*) command base64 "$@" ;; esac; }; ')
    os.unlink(inst)
    with open(os.path.join(_HOME111, _CFGDIR111, "secrets-csgoserver.cfg"), "w", encoding="utf-8") as fh:
        fh.write('rconpassword="x"\n')
    n_ok, _n_msg = _files111.lgsm_write_config(None, _USER111, "csgoserver", {"maxplayers": "20"})
    check("lgsm_write_config: ...an unreadable secrets file still lets a missing instance cfg be created "
          "(control: its mark does not hide __NOFILE__)",
          n_ok is True and os.path.isfile(inst), repr((n_ok, _n_msg)))
    _PRELUDE111["text"] = 'base64() { return 1; }; '
    content, err = _files111.read_file(None, _USER111, _CFGDIR111 + "/common.cfg")
    _PRELUDE111["text"] = ""
    content_ok, err_ok = _files111.read_file(None, _USER111, _CFGDIR111 + "/common.cfg")
    check("read_file: a read whose base64 fails is 'can't read', never an empty file the editor would save",
          content is None and err == _files111._READ_REFUSALS["__UNREADABLE__"]
          and (content_ok, err_ok) == ('defaultmap="de_dust2"\n', None), repr((content, err, content_ok)))


# ── GMod content held in another account, and a scan that did not run ───────────────────────────
def _gmod_host111():
    """A host row with a panel CS:S server whose account is `p111css`: the host's id."""
    with _p9.app_context():
        r = RemoteServer(name="p111-g", host="p111-g.example.invalid", port=22, username="admin",
                         auth_method="key", auth_credential="", is_online=True)
        db.session.add(r)
        db.session.commit()
        _mine111["hosts"].append(r.id)
        gs = GameServer(remote_id=r.id, name="p111 CS:S", short_name="p111css", game_type="css",
                        port=27111, installed=True, status="offline")
        db.session.add(gs)
        db.session.commit()
        _mine111["servers"].append(gs.id)
        return r.id


def _gmod_refusals111(rid, cases):
    """{case: (status, message) or None} for a server-only admin mounting cstrike, per scan answers."""
    scans = []
    _p9_patch(_p9_core, "run_privileged", lambda server, verb, args=(), **k: (
        scans.pop(0) if verb == "content-scan" and scans else ("", "p111: unexpected verb", 1)))
    _p9_patch(_p9_core, "run_command", lambda server, cmd, **k: ("p111grp\n", "", 0) if "id -gn" in cmd
              else ("", "p111: unexpected command", 1))
    _p9_patch(_p9_sf, "current_user", NS(is_superadmin=False))
    _p9_patch(_p9_sf, "can_access_remote", lambda user, remote_id: False)
    got = {}
    with _p9.test_request_context("/"), _p9.app_context():
        remote = db.session.get(RemoteServer, rid)
        for case, answers in cases:
            scans[:] = list(answers)
            resp = _p9_sf._sf_gmod_host_refusal(NS(remote_id=rid, name="p111 GMod"), remote, "mount", ["cstrike"])
            got[case] = (resp[1], (resp[0].get_json() or {}).get("message", "")) if resp else (None, "")
    return got


def _gmod_where111():
    """The server-only admin's refusal names where the content is, or that it could not be read."""
    box = "HIT|p111box|tf\nHIT|p111box|hl2mp\n"
    got = _gmod_refusals111(_gmod_host111(), (
        ("alt holds it", [(box + "HIT|p111alt|cstrike\n", "", 0)] * 2),
        ("second scan unread", [(box, "", 0), ("", "timed out", -1)]),
        ("nobody", [(box, "", 0)] * 2)))
    check("GMod content: a game held in a second non-server account is said to be on the host, in an "
          "account the panel does not mount from (it said 'Not on this host yet')",
          got["alt holds it"][0] == 403 and got["alt holds it"][1].startswith("On this host, but not in the account"),
          repr(got))
    check("GMod content: ...a second scan that did not answer says it could not read, not 'Not on this "
          "host yet'; a game nobody holds still is (control)",
          got["second scan unread"][1].startswith("Couldn't read what content")
          and got["nobody"][1].startswith("Not on this host yet"), repr(got))


# ── the console poller: offsets forgotten while a read is out ───────────────────────────────────
def _tick_forgotten111():
    """A viewer leaving during a tick's read: the reply is a first sight, and the tick does not raise."""
    sid = 991110
    _sf111._console_offsets[sid] = {"ino": 5, "pos": 10, "chain": 1, "fresh": False}

    def _read(remote, gs, log_path, ino, pos):
        _sf111._console_offsets.pop(sid, None)        # _forget_unwatched_consoles, mid-read
        return (5, 40, 10, 30, "x" * 30), 0
    _p9_patch(_p9_sf, "_console_poll_read", _read)
    emitted = []
    sock = NS(emit=lambda *a, **k: emitted.append(a))
    gs = NS(console_log="/home/p111/log/console/csgoserver-console.log", remote=None,
            short_name="p111", lgsm_name="csgoserver")
    try:
        _sf111._console_tick(None, sock, gs, sid)
        raised = None
    except Exception as exc:  # noqa: BLE001 - the old code raised TypeError here; the check names it
        raised = repr(exc)
    state = _sf111._console_offsets.pop(sid, None)
    feed = _sf111._console_feed.pop(sid, None) or {}
    check("console poller: offsets forgotten while a read was out make that reply a first sight (the end "
          "recorded, nothing pushed) — the tick neither raises nor counts as failed",
          raised is None and not emitted and state is not None and state.get("pos") == 40
          and state.get("fresh") is True and not feed.get("fails"), repr((raised, emitted, state, feed)))


# ── smaller fixes: default names used up, Discord's echo, the lock sweep, a retried dependency ──
def _names_used_up111():
    with _p9.app_context():
        r = RemoteServer(name="p111-n", host="p111-n.example.invalid", port=22, username="admin",
                         auth_method="key", auth_credential="", is_online=True)
        db.session.add(r)
        db.session.commit()
        _mine111["hosts"].append(r.id)
        rows = [GameServer(remote_id=r.id, name="p111n%d" % n, short_name="mcserver%d" % n, game_type="mc",
                           port=30000 + n, installed=True, status="offline") for n in range(1, 101)]
        db.session.add_all(rows)
        db.session.commit()
        _mine111["servers"] += [g.id for g in rows]
        name, n = _p9_ms._next_default_name(r.id, "mcserver", 1)
        with _p9.test_request_context("/"):
            full = _p9_ms._dedupe_install_name(r.id, "mcserver1", "", "mcserver")
        db.session.delete(rows[49])                   # mcserver50 is free again
        db.session.commit()
        _mine111["servers"].remove(rows[49].id)
        name2, n2 = _p9_ms._next_default_name(r.id, "mcserver", 1)
        with _p9.test_request_context("/"):
            short, _ch, _n, refused = _p9_ms._dedupe_install_name(r.id, "mcserver1", "", "mcserver")
    check("install: with every default name up to 100 taken there is no default name and the blank form "
          "is refused (it handed back the taken mcserver100, and a second row was made on its account)",
          name is None and full[3] is not None, repr((name, n, full)))
    check("install: ...a freed one is found (control)",
          (name2, n2) == ("mcserver50", 50) and short == "mcserver50" and refused is None,
          repr((name2, n2, short, refused)))


def _discord_echo111():
    said = []
    _p9_patch(_dc111, "_dc_reply", lambda tok, ch, text: said.append(text))
    _dc111._handle_discord_command(None, "t", "c", "![Sign in again](https://evil.example/login)")
    _dc111._handle_discord_command(None, "t", "c", "!frobnicate")
    check("discord: an unknown command is echoed without markdown (no masked link in the bot's own "
          "message); a plain one is echoed as typed (control)",
          len(said) == 2 and not any(ch in said[0] for ch in "[]()/:")
          and "'frobnicate'" in said[1], repr(said))


def _lock_sweep111():
    """An old backup.lock is kept while a backup's tar runs, and cleared while only a download's runs."""
    me = _pwd111.getpwuid(os.getuid()).pw_name
    home = os.path.realpath(_tf111.mkdtemp(prefix="lgsm-unit-p111-lock-"))
    lock = os.path.join(home, "lgsm", "lock", "backup.lock")
    got = {}
    try:
        for case, argv in (("download", ["tar", "czf", "-", "-T", "-"]),
                           ("backup", ["tar", "-hcf", os.path.join(home, "b.tar"), "-T", "-"]),
                           ("none", None)):
            os.makedirs(os.path.dirname(lock), exist_ok=True)
            with open(lock, "w", encoding="utf-8") as fh:
                fh.write("1\n")
            os.utime(lock, (1, 1))
            stand = None if argv is None else _sp111.Popen(  # nosec B603 B607 - a real tar, blocked on stdin
                argv, stdin=_sp111.PIPE, stdout=_sp111.DEVNULL, stderr=_sp111.DEVNULL, cwd=home)
            try:
                _time111.sleep(0.3)
                _sp111.run(["bash", "-c", _game111._stale_backup_lock_sweep(me, home=home) + "true"],  # nosec
                           capture_output=True, timeout=20, check=False)
                got[case] = os.path.exists(lock)
            finally:
                if stand is not None:
                    stand.kill()
                    stand.wait()
    finally:
        _shutil111.rmtree(home, ignore_errors=True)
    check("backup lock sweep: a download's `tar czf -` does not keep an orphaned lock; a backup's tar "
          "does; with no tar it is cleared (control)",
          got == {"download": False, "backup": True, "none": False}, repr(got))


def _deps_retry111():
    calls = []
    _p9_patch(_hosts111, "deps_for_game", lambda _g, _s: (["libc6:i386", "curl"], False))
    _p9_patch(_hosts111, "host_os_slug", lambda _s: "ubuntu-24.04")
    _p9_patch(_hosts111, "_listed_extras", lambda *a, **k: ([], []))
    _p9_patch(_p9_core, "run_privileged", lambda server, verb, args=(), **k: (
        calls.append((verb, list(args))),
        ("", "E: Could not get lock", 100) if verb == "apt-install-minimal" and len(args) > 1
        else ("ok", "", 0))[1])
    ok, _msg = _hosts111.install_game_dependencies(NS(is_local=False, id=None), "gmod")
    singles = [a for v, a in calls if v == "apt-install-minimal" and len(a) == 1]
    check("game deps: a failed batch whose packages then each install is a success (the retries' results "
          "were dropped and it reported 'some dependencies did not install')",
          ok is True and singles == [["libc6:i386"], ["curl"]], repr((ok, singles)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
def _cleanup111():
    _stop_writers111()
    with _p9.app_context():
        for model, key in ((GameServer, "servers"), (User, "users"), (RemoteServer, "hosts")):
            for oid in _mine111[key]:
                o = db.session.get(model, oid)
                if o is not None:
                    db.session.delete(o)
            db.session.commit()
    with _sh111._ACCOUNT_VERDICTS_LOCK:
        _sh111._ACCOUNT_VERDICTS.clear()
    _shutil111.rmtree(_HOME111, ignore_errors=True)


try:
    _p9_arm(who="part111")
    _p9_patch(_p9_core, "_run_local", _p9_trip("local-run"))
    _p9_patch(_p9_core, "shell_as_game_user", _bash111)
    _p9_patch(_sh111, "privileged_accounts", _no_privileged111)
    with _sh111._ACCOUNT_VERDICTS_LOCK:
        _sh111._ACCOUNT_VERDICTS.clear()
    _S111, _ADMIN111 = _host111()
    _A111 = _p9_client(_ADMIN111)
    _by_name111(_A111, _S111)
    _resolved111(_A111, _S111)
    _old_delete_silences111()
    _rename_dest111()
    _catalog111()
    _own_pgrep111()
    _start_answers111()
    _status_stale111()
    _cfg_reads111()
    _gmod_where111()
    _tick_forgotten111()
    _names_used_up111()
    _discord_echo111()
    _lock_sweep111()
    _deps_retry111()
finally:
    _p9_restore_all()
    _cleanup111()

check("part111: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP111_START, repr(_P9_TRIPPED[_TRIP111_START:][:6]))
