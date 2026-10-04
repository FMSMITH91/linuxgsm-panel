"""Clean reboots: stop a host's game servers gracefully, reboot it, bring back what was running.

THE INVARIANT. For every managed game server on a host the panel reboots, LinuxGSM's
`lgsm/lock/<selfname>-monitoring.lock` is in the same state after the reboot as before it. That
file is LinuxGSM's own "monitor may (re)start me" flag: `start` writes it, a `stop` the operator
typed removes it, and the `*/5 monitor` cron line the Autostart switch writes restarts a server
only while it exists. A plain reboot leaves it alone, so Autostart servers came back by themselves;
a graceful `stop` before the reboot deletes it, which is why stopping first used to mean nothing
came back. So the panel moves the lock aside before the stop and puts it back before the reboot,
and LinuxGSM's monitor brings those servers back exactly as it always did — without the panel,
which on its own host is down at the time.

The panel adds two things only: the graceful `stop` (players are told, saves are written), and,
after the boot, a start for the servers that were running but that LinuxGSM's monitor would not
bring back (no Autostart line, or no lock). Each server has exactly ONE starter, fixed when the
plan is made (`owner`):

    monitor  running, an Autostart cron line and a lock -> LinuxGSM's monitor restarts it
    panel    running otherwise                          -> the panel's SAFE START after the boot
             (or nobody, when the reboot_restore_no_autostart setting is off)
    none     running with a queued "stop when empty"    -> stays stopped; the queue is honoured
    —        not running, or could not be read          -> not touched at all: a `stop` would
                                                           delete the lock of a crashed server
                                                           LinuxGSM is about to restart

What a plan did is in GameServer.reboot_restore (JSON, committed before anything is touched), so
the restore survives the panel host's own reboot and a panel restart in the middle: the restore
worker (host_reboot_worker) reads the rows back and either finishes the plan after the boot or, if
the boot never happened, undoes it.

Reboots made outside the panel (a terminal `sudo reboot`, a provider's console) are unchanged.
"""
import base64
import concurrent.futures
import json
import logging
import os
import threading
import time
import uuid

from panel.core import runtime_stats
from panel.core.config import load_config
from panel.core.panel_state import (_action_output, _expected_offline, _full_backup_lock,
                                    _host_reboots, _hr_lock, _install_jobs, _install_lock,
                                    _monitor_state, _reboot_awaiting, _reboot_when_empty, _rwe_lock,
                                    register_remote_state)
from panel.db.models import AuditLog, GameServer, RemoteServer, db
from panel.ops import ssh_manager as _sm
from panel.ops import system_ops as so
from panel.security.auth import log_action
from panel.services import monitoring as _mon
from panel.services import notifications

_log = logging.getLogger("panel.host_reboot")

# ── Tuning ──────────────────────────────────────────────────────────────────────────────────────
# A graceful stop's budget. LinuxGSM's longest ordinary stopmode (4, `quit`) waits 120 s before it
# kills the session, plus its checks; the telnet stopmodes (8: 7 Days to Die, 13: Soulmask) poll a
# telnet console that can take minutes. The panel's usual 60 s cut the stop off mid-save.
STOP_BUDGET = 180
STOP_BUDGET_TELNET = 600
_TELNET_STOP_GAMES = frozenset(("sdtd", "sm"))
STOP_PHASE_CAP = 900             # the whole stop phase; after it the job goes on and reports stragglers
STOP_WORKERS = 4                 # accounts stopped at once (serially within one account)
# The seconds of the host's minute in which a lock may be put back. Cron starts the `*/5 monitor`
# at second 0 and LinuxGSM reads the lock about 6 s into its run, so a lock put back at :10-:40,
# with no LinuxGSM command in flight for that server, cannot be read by a monitor run that then
# finds the session gone and restarts the server the reboot is about to kill.
ARM_WINDOW = (10, 40)
ARM_WAIT = 120                   # how long the job waits for that window before it gives up
START_WINDOW = (5, 40)           # the same rule for a start the panel makes (SAFE START)
DID_NOT_HAPPEN_AFTER = 300       # same boot this long after the reboot was sent: it did not happen
LATE_NOTICE_AFTER = 600          # one "has not come back" notice after this long
NOT_BACK_AFTER = 720             # a server not running this long after the boot is reported
SETTLE_UPTIME = 60               # restore only once the host has been up this long...
SETTLE_UPTIME_MAX = 300          # ...and is not "starting", or has been up this long
START_ATTEMPTS = 3
START_RETRY_GAP = 60
STALE_PLAN = 7 * 86400           # rows this old are cleared, with a notification
STALE_SENT = 86400               # a same-boot plan sent this long ago is a restored backup: cleared
GRACE_AFTER_CLEAR = 0            # _expected_offline ts: the monitor's own 180 s window from now
BOUNCE_BACKOFF = 600
BOUNCE_NOTIFY_AT = 3
UNKNOWN_REMIND_AFTER = 1800
COUNTDOWN = (60, 30, 10)         # seconds left at each in-game warning before a forced stop
BUSY_TICK, IDLE_TICK = 15, 60
WAIT_TICK = 60

_SETTING_WAIT_HOURS = "reboot_wait_max_hours"
_SETTING_RESTORE_NO_AUTOSTART = "reboot_restore_no_autostart"
DEFAULT_WAIT_HOURS = 24

# The LinuxGSM commands whose process means "LinuxGSM is doing something to this server now", and
# the ones of those that are maintenance a reboot must not cut through.
_INFLIGHT_CMDS = ("monitor|start|stop|restart|update|force-update|validate|backup|install|"
                  "auto-install|debug|details|mods-update|update-lgsm")
_MAINT_CMDS = "update|force-update|validate|backup|install|auto-install|mods-update|update-lgsm"
_PROBE_KEYS = ("SESSION", "LOCK", "ASIDE", "CRON", "INFLIGHT", "MAINT", "BOOT", "MID", "NOW", "SEC")

# The last finished outcome per host, shown on the Power card for a day: {at, text, ok}.
_last_result = register_remote_state({})


# ── Settings ────────────────────────────────────────────────────────────────────────────────────
def wait_max_hours():
    """How long 'reboot when everyone has left' waits before it gives up; 0 waits for ever."""
    try:
        v = int(load_config().get(_SETTING_WAIT_HOURS, DEFAULT_WAIT_HOURS))
    except (TypeError, ValueError):
        return DEFAULT_WAIT_HOURS
    return max(0, min(v, 24 * 30))


def restore_no_autostart():
    """Whether a running server WITHOUT Autostart is started again after a panel reboot."""
    return bool(load_config().get(_SETTING_RESTORE_NO_AUTOSTART, True))


# ── Small helpers ───────────────────────────────────────────────────────────────────────────────
def _q(s):
    return _sm._core._quote(s)


def rr(gs):
    """A server's reboot_restore record as a dict, or None when it has none (or it is unreadable)."""
    raw = getattr(gs, "reboot_restore", None)
    if not raw:
        return None
    try:
        d = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return d if isinstance(d, dict) and d.get("v") == 1 else None


def _set_rr(gs, data):
    gs.reboot_restore = json.dumps(data, sort_keys=True) if data is not None else None


def _host_label(remote):
    try:
        return remote.display_name
    except Exception:  # noqa: BLE001 - a label must never be what raises
        return "the host"


def _actor_name(actor):
    if actor is None:
        return "system"
    return getattr(actor, "username", None) or str(actor)


def _cmd_pattern(selfname, cmds):
    """The pgrep ERE for `<selfname> <cmd>` in a LinuxGSM command line.

    `/[g]modserver (start|…)( |$)`: the slash is the one before the script name in both shapes a
    LinuxGSM command line has (`/bin/bash ./s start`, cron's `/home/u/s monitor`), so `xs start` is
    not `s start`; the bracket keeps the shell that asks from matching its own command line.
    """
    s = selfname.replace(".", "[.]")
    return "/[%s]%s (%s)( |$)" % (s[0], s[1:], cmds)


def _session_sh():
    """Shell that sets $SESS to 1 when `$s` has a live tmux session, else 0 (check_status.sh's test)."""
    # LinuxGSM's socket is `<selfname>-<uid file>` (linuxgsm.sh), or the bare session name before
    # the uid file existed (core_legacy.sh). An EXACT session name: `has-session -t` matches by
    # prefix, and codserver would answer for codserver-2.
    return ('u=$(cat "lgsm/data/$s.uid" 2>/dev/null); n=0; '
            'if [ -n "$u" ]; then n=$(TERM=screen tmux -L "$s-$u" list-sessions -F '
            '"#{session_name}" 2>/dev/null | grep -Fxc -- "$s"); fi; '
            'm=$(TERM=screen tmux -L "$s" list-sessions -F "#{session_name}" 2>/dev/null '
            '| grep -Fxc -- "$s"); '
            'if [ "${n:-0}" -gt 0 ] || [ "${m:-0}" -gt 0 ]; then SESS=1; else SESS=0; fi; ')


def _head_sh(user, selfname):
    return "cd /home/%s || exit 3; s=%s; L=lgsm/lock; " % (_q(user), _q(selfname))


def _probe_sh(user, selfname):
    """The read-only probe of one server, run as its game account. See probe_server."""
    me = '"$(id -un)"'
    return (_head_sh(user, selfname) + _session_sh()
            + 'echo "SESSION=$SESS"; '
            + 'if [ -f "$L/$s-monitoring.lock" ]; then echo LOCK=monitoring; '
              'elif [ -f "$L/$s.lock" ]; then echo LOCK=legacy; else echo LOCK=none; fi; '
            + 'if [ -f "$L/$s-monitoring.lock.panel-reboot" ]; then echo ASIDE=monitoring; '
              'elif [ -f "$L/$s.lock.panel-reboot" ]; then echo ASIDE=legacy; '
              'else echo ASIDE=none; fi; '
            + 'echo "CRON=$(crontab -l 2>/dev/null | grep -F -- "$s" | base64 -w0)"; '
            + 'echo "INFLIGHT=$(pgrep -u %s -fc %s)"; ' % (me, _q(_cmd_pattern(selfname, _INFLIGHT_CMDS)))
            + 'echo "MAINT=$(pgrep -u %s -fc %s)"; ' % (me, _q(_cmd_pattern(selfname, _MAINT_CMDS)))
            + 'echo "BOOT=$(cat /proc/sys/kernel/random/boot_id)"; '
              'echo "MID=$(cat /etc/machine-id)"; echo "NOW=$(date +%s)"; echo "SEC=$(date +%S)"; '
              'echo PROBE_OK')


_UNREAD = {"ok": False, "session": None, "lock": None, "aside": None, "cron": None,
           "inflight": None, "maint": None, "boot": None, "mid": None, "now": None, "sec": None}


def _int_or_none(v):
    try:
        return int(str(v).strip(), 10)
    except (TypeError, ValueError):
        return None


_LOCK_WORDS = ("monitoring", "legacy", "none")


def _probe_values(lines):
    raw = {}
    for ln in lines:
        k, sep, v = ln.partition("=")
        if sep and k in _PROBE_KEYS:
            raw[k] = v.strip()
    return raw


def _word(value, allowed):
    return value if value in allowed else None


def parse_probe(out):
    """probe_server's text as a dict. Every field None unless the probe's own PROBE_OK came back."""
    lines = [ln.strip() for ln in (out or "").splitlines()]
    raw = _probe_values(lines) if "PROBE_OK" in lines else {}
    sess = _word(_int_or_none(raw.get("SESSION")), (0, 1))
    if sess is None:
        return dict(_UNREAD)
    return {"ok": True, "session": sess, "lock": _word(raw.get("LOCK"), _LOCK_WORDS),
            "aside": _word(raw.get("ASIDE"), _LOCK_WORDS), "cron": _cron_lines(raw.get("CRON")),
            "inflight": _int_or_none(raw.get("INFLIGHT")), "maint": _int_or_none(raw.get("MAINT")),
            "boot": raw.get("BOOT") or None, "mid": raw.get("MID") or None,
            "now": _int_or_none(raw.get("NOW")), "sec": _int_or_none(raw.get("SEC"))}


def _cron_lines(b64):
    if b64 is None:
        return None
    try:
        return base64.b64decode(b64.encode(), validate=True).decode("utf-8", "replace").splitlines()
    except (ValueError, TypeError):
        return None


def probe_server(remote, gs_or_ident):
    """Read one server's state as its game account: one shell, never a guess. Never raises.

    {ok, session 0|1, lock monitoring|legacy|none, aside (the lock this feature moved aside, if
    any), cron (the crontab lines naming it), inflight (LinuxGSM commands for it running now),
    maint (of those, maintenance), boot, mid, now, sec (the second of the host's minute)}. Every
    field is None when the probe did not answer — the tailscale and local transports return
    ("", "...timed out", -1) without raising — and None is "unknown", never "stopped".
    """
    user, selfname = _ident(gs_or_ident)
    if not _sm.game_idents_ok(user, selfname):
        return dict(_UNREAD)
    try:
        out, _err, _rc = _account_shell(remote, user, _probe_sh(user, selfname), timeout=20,
                                        selfname=selfname)
    except Exception:  # noqa: BLE001 - paramiko raises where the other transports return
        return dict(_UNREAD)
    return parse_probe(out)


def _own_account():
    """The account the panel runs as, or None when it cannot be told. A seam for the tests."""
    try:
        import pwd
        return pwd.getpwuid(os.getuid()).pw_name
    except (ImportError, KeyError):
        return None


def _account_shell(remote, user, sh, timeout=20, selfname=None):
    """(out, err, rc) of `sh` run as the game account `user`. May raise, as the transport does.

    A game the panel runs under its OWN account, on its own host (the single-box per-user layout),
    is read and changed as that account directly: `sudo -u <itself>` needs a sudoers rule that names
    the panel's account as a run-as target, and the narrow grant names only the game accounts'
    group, so there it is refused and the server would read as unknown and be left to the shutdown.
    The helper's lgsm-command already accepts the account that invoked it, so its stop and start
    work either way.
    """
    if (_sm.is_local_server(remote) and user == _own_account()
            and _sm.game_idents_ok(user, *((selfname,) if selfname else ()))):
        return _sm.run_command(remote, sh, timeout=timeout, sudo=False)
    return _sm.shell_as_game_user(remote, user, sh, timeout=timeout, selfname=selfname)


def _ident(x):
    if isinstance(x, dict):
        return x["user"], x["selfname"]
    return x.short_name, x.lgsm_name


def has_autostart_line(cron_lines, user, selfname):
    """Whether these crontab lines hold the Autostart `monitor` line — as the Autostart switch reads it."""
    for raw in cron_lines or ():
        row = _sm.cron._cron_job_row(raw, user, selfname, {}, {})
        if row is not None and row.get("role") == "autostart":
            return True
    return False


def classify(gs, probe, no_autostart_restore=None):
    """(owner, why) for one server: who brings it back after the reboot, or None for no one.

    owner None means it is not part of the plan at all and is never stopped (see the module doc).
    """
    if probe.get("session") is None:
        return None, "unreadable"
    if probe["session"] == 0:
        return None, "stopped"
    if getattr(gs, "stop_pending", False):
        return "none", "stop_pending"
    if (probe.get("lock") in ("monitoring", "legacy")
            and has_autostart_line(probe.get("cron"), gs.short_name, gs.lgsm_name)):
        return "monitor", "autostart"
    keep = restore_no_autostart() if no_autostart_restore is None else no_autostart_restore
    return ("panel", "no_autostart") if keep else ("none", "no_autostart_off")


def _lock_sh(user, selfname, body):
    return _head_sh(user, selfname) + body


def disarm(remote, ident):
    """Move a server's monitoring lock aside so neither a stop nor a monitor run can act on it.

    'monitoring' or 'legacy' (what was moved), 'none' (there was no lock), or None when it could
    not be done or confirmed — the caller then treats the server as one the panel must start.
    """
    user, selfname = _ident(ident)
    body = ('r=none; if [ -f "$L/$s-monitoring.lock" ]; then '
            'mv -f "$L/$s-monitoring.lock" "$L/$s-monitoring.lock.panel-reboot" && r=monitoring; '
            'elif [ -f "$L/$s.lock" ]; then mv -f "$L/$s.lock" "$L/$s.lock.panel-reboot" && r=legacy; fi; '
            'if [ -f "$L/$s-monitoring.lock" ] || [ -f "$L/$s.lock" ]; then echo DISARM=fail; '
            'else echo "DISARM=$r"; fi')
    out = _game_shell(remote, user, selfname, _lock_sh(user, selfname, body))
    got = _line_values(out, "DISARM")
    return got[0] if got and got[0] in ("monitoring", "legacy", "none") else None


def _rearm_body():
    return ('if [ -f "$L/$s-monitoring.lock.panel-reboot" ]; then '
            'mv -n "$L/$s-monitoring.lock.panel-reboot" "$L/$s-monitoring.lock"; fi; '
            'if [ -f "$L/$s.lock.panel-reboot" ]; then mv -n "$L/$s.lock.panel-reboot" "$L/$s.lock"; fi; '
            'if [ -f "$L/$s-monitoring.lock" ] || [ -f "$L/$s.lock" ]; then '
            'rm -f "$L/$s-monitoring.lock.panel-reboot" "$L/$s.lock.panel-reboot"; echo "ARMED=$s"; '
            'else echo "UNARMED=$s"; fi; ')


def _drop_aside_body():
    return 'rm -f "$L/$s-monitoring.lock.panel-reboot" "$L/$s.lock.panel-reboot"; echo "DROPPED=$s"; '


def put_locks_back(remote, user, entries):
    """Re-arm the 'monitor' servers of ONE account and drop the 'none' ones' aside files, in one shell.

    `entries` is [(selfname, owner)]. Returns the set of selfnames confirmed armed (monitor) or
    cleaned (none); a server missing from it was not confirmed.
    """
    parts = []
    for selfname, owner in entries:
        if not _sm.game_idents_ok(user, selfname):
            continue
        body = _rearm_body() if owner == "monitor" else _drop_aside_body()
        parts.append("( s=%s; L=lgsm/lock; %s)" % (_q(selfname), body))
    if not parts:
        return set()
    sh = "cd /home/%s || exit 3; %s" % (_q(user), " ; ".join(parts))
    out = _game_shell(remote, user, entries[0][0], sh)
    return set(_line_values(out, "ARMED") + _line_values(out, "DROPPED"))


def _line_values(out, key):
    """The value of every `KEY=value` line in a script's own output, in order."""
    lead = key + "="
    return [ln.strip()[len(lead):] for ln in (out or "").splitlines() if ln.strip().startswith(lead)]


def _game_shell(remote, user, selfname, sh, timeout=20):
    """Run `sh` as the game account; its stdout, or "" when it did not run. Never raises."""
    try:
        out, _err, _rc = _account_shell(remote, user, sh, timeout=timeout, selfname=selfname)
    except Exception:  # noqa: BLE001 - paramiko raises where the other transports return
        return ""
    return out or ""


def in_window(sec, window):
    """Whether the second-of-minute `sec` falls inside `window` (inclusive); False when unknown."""
    return isinstance(sec, int) and window[0] <= sec <= window[1]


# ── SAFE START ──────────────────────────────────────────────────────────────────────────────────
def _start_gate_sh(user, selfname):
    """Shell that opens a start: inside the window, nothing in flight, no session yet."""
    pat = _q(_cmd_pattern(selfname, _INFLIGHT_CMDS))
    return (_head_sh(user, selfname)
            + 'sec=$((10#$(date +%%S))); if [ "$sec" -lt %d ] || [ "$sec" -gt %d ]; then '
              'echo GATE=window; exit 0; fi; ' % START_WINDOW
            + 'if [ "$(pgrep -u "$(id -un)" -fc %s)" != 0 ]; then echo GATE=inflight; exit 0; fi; ' % pat
            + _session_sh()
            + 'if [ "$SESS" = 1 ]; then echo GATE=running; exit 0; fi; '
            + 'if [ -d "$L" ]; then date +%s > "$L/$s-starting.lock"; fi; '
            + 'rm -f "$L/$s-monitoring.lock.panel-reboot" "$L/$s.lock.panel-reboot"; echo GATE=open')


def _open_start(remote, user, selfname):
    """None when a start may go ahead now (its -starting.lock written), else (outcome, detail)."""
    gate = _line_values(_game_shell(remote, user, selfname, _start_gate_sh(user, selfname)), "GATE")
    word = gate[0] if gate else None
    if word == "open":
        return None
    if word == "running":
        return "running", ""
    if word in ("window", "inflight"):
        return "wait", word
    return "wait", "the host did not answer"


def safe_start(remote, ident):
    """Start one server the way LinuxGSM's own monitor will not race: (outcome, detail).

    outcome: 'started' | 'running' (it already was) | 'wait' (not now: outside the window, or a
    LinuxGSM command in flight; try on a later tick) | 'failed'.

    The `-starting.lock` written first is the one the monitor reads (command_monitor.sh): with it,
    and the start's own `/bin/bash ./<s> start` process, a monitor run that overlaps backs off
    instead of starting a second copy — which would take the console log's pipe from the first.
    """
    user, selfname = _ident(ident)
    opened = _open_start(remote, user, selfname)
    if opened is not None:
        return opened
    try:
        out, err, rc = _sm.run_as_game_user(remote, user, "start", timeout=300, selfname=selfname)
    except Exception:  # noqa: BLE001
        out, err, rc = "", "the start could not be run", -1
    if rc in (0, 2):              # 2: "already running" (command_start.sh) is the same outcome
        return "started", ""
    if probe_server(remote, ident).get("session") == 1:
        return "started", ""
    from panel.routes.server_detail import _action_failure_reason, _clean_action_output
    reason = _action_failure_reason(_clean_action_output((out or "") + "\n" + (err or "")).strip())
    return "failed", (reason or "exit status %s" % rc)[:200]


# ── The census: one predicate for the dialog, the gate, the waiter ──────────────────────────────
def _blocker(kind, name, detail=""):
    return {"kind": kind, "name": name, "detail": detail}


def _row_blockers(rows):
    out = []
    from panel.routes._shared import _backup_in_progress
    for gs in rows:
        if gs.status in ("installing", "configuring"):
            out.append(_blocker("install", gs.name))
            continue
        with _install_lock:
            job = _install_jobs.get(gs.id)
        if job and job.get("status") == "running":
            out.append(_blocker("install", gs.name))
        if _backup_in_progress(gs.id):
            out.append(_blocker("backup", gs.name))
        act = _action_output.get(gs.id)
        if act and not act.get("ended"):
            out.append(_blocker("action", gs.name, act.get("action") or ""))
        if _content_running(gs.id):
            out.append(_blocker("content", gs.name))
    return out


def _content_running(gid):
    try:
        from panel.routes.server_files import _gmod_content_apply_state
    except Exception:  # noqa: BLE001
        return False
    st = _gmod_content_apply_state.get(gid)
    return bool(st and st.get("status") == "running")


def _host_blockers(remote):
    out = []
    from panel.routes._shared import _bootstrap_jobs, _bootstrap_lock
    with _bootstrap_lock:
        bj = _bootstrap_jobs.get(remote.id)
    if bj and bj.get("status") in ("running", "rebooting"):
        out.append(_blocker("bootstrap", _host_label(remote)))
    for verb, kind in (("dpkg-lock-held", "dpkg"), ("apt-any-running", "apt")):
        try:
            _o, _e, rc = _sm.run_privileged(remote, verb, [], timeout=10, merge_stderr=False)
        except Exception:  # noqa: BLE001 - unanswered is not "held"; the preflight reads the host
            rc = None
        if rc == 0:
            out.append(_blocker(kind, _host_label(remote)))
    if _sm.is_local_server(remote):
        out.extend(_panel_host_blockers())
    return out


def _panel_host_blockers():
    out = []
    try:
        if so._update_in_progress():
            out.append(_blocker("self_update", "the panel"))
    except Exception:  # noqa: BLE001
        _log.debug("self-update state unreadable", exc_info=True)
    from panel.ops import backup as _bk
    if _bk._restore_lock.locked():
        out.append(_blocker("restore", "the panel"))
    if _full_backup_lock.locked():
        out.append(_blocker("full_backup", "the panel"))
    return out


def _loaded(obj):
    """`obj` with every column read HERE: a pool thread has no app context to load it in."""
    from sqlalchemy import inspect as _sa_inspect
    try:
        for key in _sa_inspect(obj).mapper.column_attrs.keys():
            getattr(obj, key)
    except Exception:  # noqa: BLE001 - not a mapped row, or detached and complete already
        _log.debug("could not load %r before handing it to a pool thread", obj, exc_info=True)
    return obj


def _probe_rows(remote, rows):
    """{gs.id: probe} for these rows: parallel across accounts (at most 4), serial within one."""
    _loaded(remote)
    by_user = {}
    for gs in rows:
        by_user.setdefault(gs.short_name, []).append({"id": gs.id, "user": gs.short_name,
                                                      "selfname": gs.lgsm_name})
    if not by_user:
        return {}

    def _one(idents):
        return [(i["id"], probe_server(remote, i)) for i in idents]
    res = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(STOP_WORKERS, len(by_user))) as ex:
        for pairs in ex.map(_one, list(by_user.values())):
            res.update(pairs)
    return res


def _count_players(running, primaries):
    """(busy, unknown) for the running rows: gamedig via the host's batch, then the fallbacks."""
    busy, unknown = [], []
    for gs in running:
        try:
            pc = _mon._server_slots(gs, primary=primaries.get(gs.id))[0]
        except Exception:  # noqa: BLE001 - an unread count is unknown, never 0
            pc = None
        if pc is None:
            why = "query_failed" if _sm.is_player_queryable(gs.game_type, gs.query_type) else "not_queryable"
            unknown.append({"id": gs.id, "name": gs.name, "reason": why,
                            "queryable": why == "query_failed"})
        elif pc > 0:
            busy.append({"id": gs.id, "name": gs.name, "players": pc})
    return busy, unknown


def host_player_state(remote, probes=None):
    """Who is on this host, and what would stop a reboot: the ONE predicate every path asks.

    {state: idle|busy|unknown|blocked|unreachable, total, running, busy:[{id, name, players}],
    unknown:[{id, name, reason}], blockers:[{kind, name, detail}], probes}. A server is counted
    only when its session is live (a stopped one has nobody on it and is not asked); a session
    that could not be read is unknown, as is a count that could not be read. Never raises.
    """
    if not _mon._host_reachable(remote):
        return {"state": "unreachable", "total": 0, "running": 0, "busy": [], "unknown": [],
                "blockers": [], "probes": {}}
    rows = GameServer.query.filter_by(remote_id=remote.id).all()
    blockers = _row_blockers(rows) + _host_blockers(remote)
    installed = _settled_rows(rows)
    if probes is None:
        probes = _probe_rows(remote, installed)
    unknown = _unread_rows(installed, probes)
    running = [gs for gs in installed if _session_of(probes, gs) == 1]
    blockers += [_blocker("maintenance", gs.name) for gs in running if probes[gs.id].get("maint")]
    busy, unk2 = _count_players(running, _mon._batched_slots(running) if running else {})
    unknown += unk2
    return {"state": _state_word(blockers, busy, unknown),
            "total": sum(b["players"] for b in busy), "running": len(running),
            "busy": busy, "unknown": unknown, "blockers": blockers, "probes": probes}


def _settled_rows(rows):
    """The rows with a game installed and no install running: the ones a reboot can stop."""
    return [gs for gs in rows if gs.installed and gs.status not in ("installing", "configuring")]


def _unread_rows(installed, probes):
    return [{"id": gs.id, "name": gs.name, "reason": "probe_failed", "queryable": True}
            for gs in installed if _session_of(probes, gs) is None]


def _session_of(probes, gs):
    return (probes.get(gs.id) or {}).get("session")


def _state_word(blockers, busy, unknown):
    if blockers:
        return "blocked"
    if busy:
        return "busy"
    return "unknown" if unknown else "idle"


# ── Preflight and preview ───────────────────────────────────────────────────────────────────────
def escalation(remote):
    """Whether the panel can run a privileged command on this host now: 'ok', 'refused' or 'silent'.

    'silent' is a host that did not answer at all — paramiko raising, the tailscale and local
    transports' timeout (-1), or ssh failing to connect (255) — which is not a sudo refusal and is
    not reported as one.
    """
    if _sm.is_local_server(remote):
        return "ok" if so._can_escalate() else "refused"
    try:
        _o, _e, rc = _sm.run_command(remote, "true", timeout=15, sudo=True)
    except Exception:  # noqa: BLE001 - paramiko raises where the other transports return
        return "silent"
    if rc == 0:
        return "ok"
    return "silent" if rc in (-1, 255) else "refused"


def can_escalate(remote):
    """Whether the panel can run a privileged command on this host right now."""
    return escalation(remote) == "ok"


def _escalation_refusal(remote):
    """None when the panel can escalate on this host, else the sentence that says why not."""
    esc = escalation(remote)
    if esc == "silent":
        return "%s did not answer, so it was not rebooted." % _host_label(remote)
    if esc != "ok":
        return ("The panel cannot run privileged commands on %s (sudo is refused), so it could "
                "not reboot it." % _host_label(remote))
    return None


def preflight(remote, census=None):
    """(ok, reason) before anything is touched: reason is a sentence, or None when it may go ahead.

    The privilege to reboot (and to stop and start), the boot check the restore depends on, and
    nothing in flight. A refusal here leaves every server exactly as it was.
    """
    refusal = _escalation_refusal(remote)
    if refusal:
        return False, refusal
    if _sm.hosts.host_boot_identity(remote) is None:
        return False, "%s did not answer the boot check." % _host_label(remote)
    if census is not None and census.get("blockers"):
        return False, _blocked_sentence(census["blockers"])
    return True, None


def preflight_warning(remote, servers):
    """The panel-host warning for a preview: the servers the PANEL starts need the panel at boot."""
    owners = {str(sv["id"]): sv["owner"] for sv in servers or ()}
    if (_sm.is_local_server(remote) and "panel" in owners.values()
            and so.panel_starts_at_boot() is False):
        return PANEL_WONT_RETURN
    return None


PANEL_WONT_RETURN = ("The panel itself is not set to start at boot, so the servers it starts after "
                     "the reboot (those without Autostart) stay stopped until it is started.")


_BLOCKER_WORDS = {"install": "an install of %s", "backup": "a backup of %s",
                  "action": "a LinuxGSM action on %s", "content": "a content install on %s",
                  "maintenance": "LinuxGSM maintenance on %s", "bootstrap": "a bootstrap of %s",
                  "dpkg": "a package install on %s", "apt": "a package install on %s",
                  "self_update": "an update of %s", "restore": "a restore of %s",
                  "full_backup": "a full backup of %s"}


def _blocked_sentence(blockers):
    what = ", ".join(_BLOCKER_WORDS.get(b["kind"], "work on %s") % b["name"] for b in blockers[:4])
    return "Not now: %s is running, and a reboot would cut it off." % what


_WHY_WORDS = {"autostart": "comes back by Autostart about 5 min after boot",
              "no_autostart": "is started by the panel after the boot",
              "no_autostart_off": "stays stopped (Autostart is off)",
              "stop_pending": "stays stopped (a stop was queued)",
              "stopped": "is stopped and stays stopped",
              "unreadable": "could not be read; it is left to the shutdown"}


def preview(remote, probes=None):
    """What a reboot now would do to each server: [{id, name, session, owner, why, text}]. Read-only."""
    rows = [gs for gs in GameServer.query.filter_by(remote_id=remote.id, installed=True).all()]
    if probes is None:
        probes = _probe_rows(remote, rows)
    out = []
    for gs in rows:
        p = probes.get(gs.id) or dict(_UNREAD)
        owner, why = classify(gs, p)
        out.append({"id": gs.id, "name": gs.name, "session": p.get("session"), "owner": owner,
                    "why": why, "text": _WHY_WORDS.get(why, "")})
    return out


# ── Status ──────────────────────────────────────────────────────────────────────────────────────
def job_of(remote_id):
    """A copy of the live job for this host, or None."""
    with _hr_lock:
        job = _host_reboots.get(remote_id)
        return dict(job) if job else None


def reboot_busy(remote_id):
    """True while the panel is stopping this host's servers to reboot it (until the reboot is sent).

    Every action that could start, stop or reconfigure a server on the host is refused meanwhile:
    the plan has decided who brings each server back, and a start in the middle makes two starters.
    """
    with _hr_lock:
        job = _host_reboots.get(remote_id)
        return bool(job) and job.get("phase") != "rebooting"


BUSY_MESSAGE = ("%s is being rebooted: its game servers are being stopped first. Try again once "
                "it is back.")


def panel_host_busy():
    """BUSY_MESSAGE for the panel's own host while it is being rebooted, else None. Never raises.

    For the panel-host routes that have no host row in hand (its self-update, its OS update): a
    lookup that fails refuses nothing, as the reboot route's own lookup does.
    """
    try:
        local = RemoteServer.query.filter_by(is_local=True).first()
    except Exception:  # noqa: BLE001 - a courtesy check never blocks on an unreadable row
        return None
    if local is not None and reboot_busy(local.id):
        return BUSY_MESSAGE % _host_label(local)
    return None


def plan_rows(remote_id):
    """The rows of this host that still have a reboot_restore record."""
    return [gs for gs in GameServer.query.filter_by(remote_id=remote_id)
            .filter(GameServer.reboot_restore.isnot(None)).all() if rr(gs)]


def status(remote):
    """What the Power card shows: {wait, job, rows, last}. Read from memory and the rows only."""
    with _rwe_lock:
        wait = dict(_reboot_when_empty.get(remote.id) or {}) or None
    job = job_of(remote.id)
    if job:
        job.pop("cancel", None)
        job["servers"] = [dict(s) for s in job.get("servers") or ()]
    rows = []
    for gs in plan_rows(remote.id):
        d = rr(gs)
        rows.append({"id": gs.id, "name": gs.name, "owner": d.get("owner"),
                     "restore": d.get("restore"), "stop": d.get("stop")})
    last = _last_result.get(remote.id)
    if last and time.time() - last.get("at", 0) > 86400:
        last = None
    return {"wait": wait, "job": job, "rows": rows, "last": last}


# ── The entry point every path goes through ─────────────────────────────────────────────────────
_MODES = {"now": "now", "force": "now", "when_empty": "when_empty", "wait": "when_empty"}
_TRUE = (True, 1, "true", "1")
_FALSE = (False, 0, "false", "0", None)


def parse_mode(body):
    """(mode, error) from a reboot request body: mode 'now', 'when_empty' or None (ask).

    `mode` wins; the older `when_empty` (true/false) and `force` (true) still work. A value that is
    none of these is an error, never a guess: bool("false") armed a wait.
    """
    body = body if isinstance(body, dict) else {}
    if body.get("mode") is not None:
        mode = _MODES.get(str(body.get("mode")).strip().lower())
        return (mode, None) if mode else (None, "mode must be 'now' or 'when_empty'")
    if body.get("force") in _TRUE:
        return "now", None
    we = body.get("when_empty")
    if isinstance(we, str):
        we = we.strip().lower()
    if we in _TRUE and we is not False:
        return "when_empty", None
    if we in _FALSE or we == "":
        return None, None
    return None, "when_empty must be true or false"


def _pending_conflict(remote):
    job = job_of(remote.id)
    if job:
        return {"success": False, "error": "in_progress", "phase": job.get("phase"),
                "message": "%s is already being rebooted (%s)." % (_host_label(remote),
                                                                    job.get("phase"))}
    if plan_rows(remote.id):
        return {"success": False, "error": "in_progress", "phase": "restoring",
                "message": ("%s's last reboot is still bringing its servers back. Try again once "
                            "that has finished." % _host_label(remote))}
    return None


def request_reboot(remote, mode, actor, origin, delay=0):
    """Ask for a clean reboot of `remote`: (http status, json payload). See the module doc.

    mode None asks for the choice when anyone (or a count nobody can read) is on the host;
    'now' runs the plan at once; 'when_empty' arms the wait. Every message stands on its own, so
    a toast in a tab opened before this change, or a script's log, is readable.
    """
    conflict = _pending_conflict(remote)
    if conflict:
        return 409, conflict
    if mode == "when_empty":
        return arm_wait(remote, actor, origin)
    census = host_player_state(remote)
    if census["state"] == "unreachable":
        return 409, {"success": False, "error": "unreachable",
                     "message": "%s is not answering, so it was not rebooted." % _host_label(remote)}
    if census["state"] == "blocked":
        return 409, _blocked_payload(remote, census)
    if mode is None and census["state"] in ("busy", "unknown"):
        return 409, _choice_payload(remote, census)
    return _reboot_now(remote, actor, origin, census, delay)


def warnable(census):
    """The servers a forced reboot warns in-game first: [{id, name}].

    Players on it, or a count nobody could read (players may be on it), AND a game whose console
    can show a message. A count that can't be read is not an empty server, so it is warned too.
    """
    rows = list(census.get("busy") or ()) + list(census.get("unknown") or ())
    ids = [r["id"] for r in rows]
    if not ids:
        return []
    says = {gs.id: bool(_sm.moderation_caps(gs.game_type).get("say"))
            for gs in GameServer.query.filter(GameServer.id.in_(ids)).all()}
    return [{"id": r["id"], "name": r["name"]} for r in rows if says.get(r["id"])]


def _public_census(census):
    return {k: census[k] for k in ("state", "total", "running", "busy", "unknown", "blockers")}


def _blocked_payload(remote, census):
    return {"success": False, "error": "blocked", "needs_choice": True, "choices": ["when_empty"],
            "blockers": census["blockers"], "players": _public_census(census),
            "message": _blocked_sentence(census["blockers"]) + (
                " Choose 'reboot when it's finished' to reboot %s once it is." % _host_label(remote))}


def _choice_payload(remote, census):
    n = census["total"]
    who = ("%d player%s online" % (n, "" if n == 1 else "s")) if n else "players may be online"
    return {"success": False, "error": "players_online", "needs_choice": True,
            "choices": ["when_empty", "now"], "players": _public_census(census),
            "message": ("Not rebooted: %s on %s. Choose to reboot when everyone has left, or "
                        "now (disconnecting them)." % (who, _host_label(remote)))}


def _reboot_now(remote, actor, origin, census, delay):
    ok, reason = preflight(remote, census)
    warning = (preflight_warning(remote, preview(remote, probes=census.get("probes") or {}))
               if _sm.is_local_server(remote) else None)
    if not ok:
        return 409, {"success": False, "error": "preflight", "reason": reason, "message": reason}
    with _rwe_lock:
        had = _reboot_when_empty.pop(remote.id, None)
    if had:
        log_action(actor, "reboot_when_empty_cancel", target=remote.name, detail="superseded",
                   remote=remote)
    warn = warnable(census)         # for the answer's words; the job warns from its own census
    started = start_clean_reboot(remote, actor, origin, "now", delay=delay)
    if not started:
        return 409, _pending_conflict(remote) or {"success": False, "error": "in_progress",
                                                  "message": "A reboot is already running."}
    # Not "then they come back": a queued stop, or restoring turned off, keeps a server stopped.
    # And the warning only where it is sent: a game with no console message gets none.
    msg = ("Rebooting %s: its running game servers are stopped cleanly first%s. The Power card shows "
           "what comes back." % (_host_label(remote),
                                 " (after a %d-second in-game warning, on the servers whose game "
                                 "can show one)" % COUNTDOWN[0] if warn else ""))
    body = {"success": True, "message": msg, "phase": "preflight"}
    if warning:
        body["warning"] = warning
    return 202, body


# ── Wait for empty ──────────────────────────────────────────────────────────────────────────────
def _arm_refusal(remote):
    """(None, ident) when a wait armed now could reboot this host when it fires, else (reason, None).

    The same privilege and boot checks the reboot itself makes: a wait that cannot succeed is
    refused now, while the operator is looking, not 24 h of retries later.
    """
    refusal = _escalation_refusal(remote)
    if refusal:
        return refusal, None
    ident = _sm.hosts.host_boot_identity(remote)
    if ident is None:
        return "%s did not answer the boot check." % _host_label(remote), None
    return None, ident


def arm_wait(remote, actor, origin):
    """Arm 'reboot when everyone has left' for this host: (http status, json payload). Idempotent.

    A fresh wait is armed only after _arm_refusal passes; one already armed is answered as it is.
    """
    ident = None
    for _attempt in range(2):
        with _rwe_lock:
            armed = remote.id in _reboot_when_empty
        if not armed and ident is None:
            reason, ident = _arm_refusal(remote)
            if reason:
                return 409, {"success": False, "error": "preflight", "reason": reason,
                             "message": reason}
        hours = wait_max_hours()
        got = _arm_now(remote, actor, origin, ident, hours)
        if got is not None:
            return 200, _armed_payload(remote, got, hours)
    return 409, {"success": False, "error": "in_progress",
                 "message": "The reboot wait of %s changed while it was being set; try again."
                            % _host_label(remote)}


def _arm_now(remote, actor, origin, ident, hours):
    """The host's wait, armed now if it was not: a copy of it, or None when it must be checked first.

    None: no wait is armed and this host was not checked (`ident` None) — it was seen armed, and a
    Cancel took that wait since. A blind arm here would skip the very checks _arm_refusal makes.
    """
    now = time.time()
    with _rwe_lock:
        info = _reboot_when_empty.get(remote.id)
        fresh = info is None
        if fresh and ident is None:
            return None
        if fresh:
            info = {"by": _actor_name(actor), "since": now, "origin": origin,
                    "expires": (now + hours * 3600) if hours else None,
                    "boot": ident.get("boot"), "waiting_on": None, "checked_at": None,
                    "unknown_since": None, "reminded": False, "bounces": 0, "not_before": 0}
            _reboot_when_empty[remote.id] = info
        info = dict(info)
    if fresh:
        log_action(actor, "reboot_when_empty_arm", target=remote.name, detail=origin or "",
                   remote=remote)
    return info


def _armed_payload(remote, info, hours):
    return {"success": True, "pending": True, "waiting_on": info.get("waiting_on"),
            "expires_at": info.get("expires"),
            "message": ("%s will reboot once nobody is on its game servers%s. It shows on the "
                        "host's Power card, where you can cancel it." % (
                            _host_label(remote), (" (it gives up after %d h)" % hours) if hours else ""))}


def cancel(remote, actor):
    """Cancel this host's pending wait, and a job that has not sent its reboot: (status, payload).

    Both under _hr_lock, then _rwe_lock: the order every holder of the two takes them. A job about
    to put its wait back (_Job._back_to_waiting), a wait about to become a job (start_clean_reboot
    from_wait), and a job about to send its reboot (_Job._send) each take _hr_lock to do it, so a
    Cancel cannot fall between them: either it lands first and they see it, or they land first and
    it sees their result. Never "cancelled" and then a reboot.
    """
    who = _actor_name(actor)
    with _hr_lock:
        with _rwe_lock:
            had = _reboot_when_empty.pop(remote.id, None)
        job = _host_reboots.get(remote.id)
        stoppable = bool(job) and job.get("sent") is None
        if stoppable:
            job["cancel"] = who
    if had:
        log_action(actor, "reboot_when_empty_cancel", target=remote.name, remote=remote)
    if stoppable:
        return 200, {"success": True, "pending": False,
                     "message": ("Cancelling the reboot of %s. The Power card shows what comes "
                                 "back." % _host_label(remote))}
    if had:
        return 200, {"success": True, "pending": False, "message": "Auto-reboot canceled."}
    if job:
        return 409, {"success": False, "error": "sent",
                     "message": "Too late to cancel: the reboot has been sent."}
    return 200, {"success": True, "pending": False, "message": "Nothing was scheduled."}


# ── The job ─────────────────────────────────────────────────────────────────────────────────────
def _spawn(target):
    """Run `target` on a daemon thread named host-reboot-job. A seam: the tests run it in line."""
    threading.Thread(target=target, name="host-reboot-job", daemon=True).start()


def start_clean_reboot(remote, actor, origin, mode, delay=0, app=None, from_wait=False):
    """Start the clean-reboot job for `remote` in the background: False when it was not started.

    It returns at once; the job's progress is _host_reboots[remote.id] (status()), its outcome a
    host_reboot notification and the audit rows. Not started: a job is already running, or (with
    `from_wait`) there is no wait to fire any more.

    `from_wait` fires the host's 'reboot when everyone has left': the wait is popped and the job
    registered under _hr_lock together, so a Cancel finds one or the other and never neither (see
    cancel()). The wait goes to the job, as whoever armed it, and comes back from the job if the
    host turns out not to be ready.
    """
    if app is None:
        from flask import current_app
        app = current_app._get_current_object()
    now = time.time()
    job = {"plan": uuid.uuid4().hex, "phase": "preflight", "mode": mode, "by": _actor_name(actor),
           "origin": origin, "since": now, "sent": None, "servers": [], "done": None,
           "total": None, "left": None, "cancel": None, "delay": int(delay or 0), "boot": None,
           "mid": None}
    wait_info = None
    with _hr_lock:
        if remote.id in _host_reboots:
            return False
        if from_wait:
            with _rwe_lock:
                wait_info = _reboot_when_empty.pop(remote.id, None)
            if wait_info is None:
                return False      # cancelled, or superseded by Reboot now, since the census
            actor = wait_info.get("by") or "system"
            job["by"] = actor
        _host_reboots[remote.id] = job
    runner = _Job(app, remote, job, actor, wait_info)
    try:
        _spawn(runner.run)
    except Exception:  # noqa: BLE001 - a job that never started must not hold the host
        with _hr_lock:
            _host_reboots.pop(remote.id, None)
            if wait_info is not None:
                with _rwe_lock:
                    _reboot_when_empty.setdefault(remote.id, wait_info)
        raise
    return True


class _Cancelled(Exception):
    """The operator cancelled the job; what it did is rolled back."""


class _Job:
    """One clean reboot of one host, run on its own thread. See the module doc for the steps."""

    def __init__(self, app, remote, job, actor, wait_info):
        """Hold what the thread needs: never the request's objects, which belong to its session."""
        from panel.db.models import row_birth
        self.app, self.job = app, job
        self.remote_id, self.born = remote.id, row_birth(remote)
        self.actor_id = getattr(actor, "id", None)
        self.by = _actor_name(actor)
        self.warn, self.wait_info = [], wait_info   # warn: the servers its countdown warned
        self.remote = None
        self.entries = []          # the plan: [{id, name, user, selfname, game_type, owner, ...}]
        self.disconnected = 0
        self.bounce = False
        self.deadline = None       # the end of the stop phase's budget (STOP_PHASE_CAP)
        self.fired = False         # this job is a wait's, and its fire was audited and announced
        self.rolled_back = False   # a bounce has already (quietly) undone the stops

    # ── plumbing ──
    def _phase(self, phase, done=None, total=None, left=None):
        """The job's phase for the Power card, with its numbers only: the page words them."""
        with _hr_lock:
            self.job.update(phase=phase, done=done, total=total, left=left)
            self.job["servers"] = [{"name": e["name"], "owner": e["owner"], "stop": e.get("stop")}
                                   for e in self.entries]

    def _cancelled(self):
        with _hr_lock:
            return self.job.get("cancel")

    def _check_cancel(self):
        """Raise _Cancelled when the operator has cancelled the job."""
        if self._cancelled():
            raise _Cancelled()

    def _sleep(self, seconds):
        """Sleep, checking for a cancel every second; raises _Cancelled."""
        end = time.monotonic() + max(0, seconds)
        while True:
            self._check_cancel()
            left = end - time.monotonic()
            if left <= 0:
                return
            time.sleep(min(1.0, left))

    def _user(self):
        """The operator's User row in THIS thread's session, or None for a wait or a script."""
        from panel.db.models import User
        return db.session.get(User, self.actor_id) if self.actor_id is not None else None

    def run(self):
        """The thread's body: never raises, and never leaves the host's servers half-stopped."""
        try:
            with self.app.test_request_context():
                self._load_and_run()
        except Exception:  # noqa: BLE001 - logged, then everything done so far is undone
            _log.exception("clean reboot of host %s failed", self.remote_id)
            self._undo_safely("the reboot job failed")
        finally:
            with _hr_lock:
                if self.job.get("phase") != "rebooting" and _host_reboots.get(self.remote_id) is self.job:
                    _host_reboots.pop(self.remote_id, None)

    def _undo_safely(self, reason):
        try:
            with self.app.test_request_context():
                if plan_rows(self.remote_id):
                    rollback(self.remote_id, reason, wait=0)
        except Exception:  # noqa: BLE001
            _log.exception("rolling back the reboot of host %s failed", self.remote_id)

    def _load_and_run(self):
        from panel.db.models import claim_row
        remote = claim_row(RemoteServer, self.remote_id, self.born)
        if remote is None:
            return
        db.session.expunge(remote)
        self.remote = remote
        try:
            self._steps()
        except _Cancelled:
            self._on_cancel()

    def _on_cancel(self):
        who = self._cancelled() or "an operator"
        if self.job["mode"] == "when_empty":
            # The wait is over: a restart must not announce it as one it dropped.
            log_action(None, "reboot_when_empty_cancel", target=self.remote.name,
                       detail="cancelled while its reboot was being prepared", actor=who,
                       remote=self.remote)
        stopped = sum(1 for e in self.entries if e.get("stop") == "stopped")
        if plan_rows(self.remote_id):
            rollback(self.remote_id, "cancelled by %s" % who, wait=75)
        elif self.rolled_back and stopped:
            # A bounce already undid the stops, quietly: say it, and that it was the operator's.
            self._finish_note(False, "The reboot of %s was cancelled by %s. The %d game server%s it "
                                     "had stopped %s being brought back." % (
                                         _host_label(self.remote), who, stopped,
                                         "" if stopped == 1 else "s", "is" if stopped == 1 else "are"))
        else:
            self._say_all(self.warn, lambda _gs: "The restart was cancelled.")
            self._finish_note(False, "The reboot of %s was cancelled by %s; nothing had been "
                                     "stopped yet." % (_host_label(self.remote), who))

    def _finish_note(self, ok, text):
        _last_result[self.remote_id] = {"at": time.time(), "text": text, "ok": ok}
        notifications.notify("host_reboot", "Host reboot", text)

    # ── the steps ──
    def _steps(self):
        if self.job.get("delay"):
            self._phase("preflight", left=self.job["delay"])
            self._sleep(self.job["delay"])
        census = self._census_or_stop()
        if census is None:
            return
        if self.job["mode"] == "now":
            warn = warnable(census)
            if warn:
                self._countdown(warn, census)
        self._make_plan(census)
        self._stop_phase()
        if self._bounced():
            return
        self._rescan()
        self._send()             # its first step: a Cancel that came in by now ends the job there

    def _census_or_stop(self):
        """The census and preflight; None when the job ends here (nothing touched)."""
        remote = self.remote
        census = host_player_state(remote)
        when_empty = self.job["mode"] == "when_empty"
        if when_empty and census["state"] != "idle":
            self._back_to_waiting(census, bounce=False)
            return None
        if census["state"] in ("unreachable", "blocked"):
            reason = ("%s is not answering" % _host_label(remote) if census["state"] == "unreachable"
                      else _blocked_sentence(census["blockers"]))
            return self._refused(reason, census)
        ok, reason = preflight(remote, census)
        if not ok:
            return self._refused(reason, census)
        ident = _sm.hosts.host_boot_identity(remote)
        if ident is None:
            return self._refused("%s did not answer the boot check." % _host_label(remote), census)
        with _hr_lock:
            self.job["boot"], self.job["mid"] = ident["boot"], ident["mid"]
        self.disconnected = census["total"] if self.job["mode"] == "now" else 0
        if when_empty:
            self._announce_fire()
        return census

    def _announce_fire(self):
        """A wait's job that passed its checks: now, and only now, it is audited and announced."""
        self.fired = True
        log_action(None, "reboot_when_empty_fire", target=self.remote.name,
                   detail="host idle — the clean reboot started", actor=self.by, remote=self.remote)
        notifications.notify("auto_reboot", "Host auto-rebooting",
                             "%s is empty of players, so its queued reboot is running: its running "
                             "game servers are stopped cleanly first. The Power card shows what comes "
                             "back." % _host_label(self.remote))

    def _refused(self, reason, census):
        if self.job["mode"] == "when_empty":
            self._back_to_waiting(census, bounce=False, reason=reason, refused=True)
            return None
        log_action(self._user(), "remote_reboot", target=self.remote.name, success=False,
                   detail="not rebooted: %s" % reason, actor=None if self.actor_id else self.by,
                   remote=self.remote)
        self._finish_note(False, "%s was not rebooted: %s" % (_host_label(self.remote), reason))
        return None

    def _back_to_waiting(self, census, bounce, reason=None, refused=False):
        """The wait this job fired goes back to waiting — unless the operator cancelled meanwhile.

        Raises _Cancelled then: the check and the put-back are one step under _hr_lock, as cancel()
        takes it, so an accepted Cancel never leaves a wait behind to reboot the host later.
        """
        info = self._wait_back(census, bounce, reason, refused)
        tell = refused and not info.get("refused_told")
        if tell:
            info["refused_told"] = True
        with _hr_lock:
            cancelled = self.job.get("cancel")
            if not cancelled:
                with _rwe_lock:
                    _reboot_when_empty.setdefault(self.remote_id, info)
        if cancelled:
            raise _Cancelled()
        self._waiting_again(info, bounce, tell, reason)

    def _wait_back(self, census, bounce, reason, refused):
        """The wait as it goes back: what it waits on now, and a back-off after a bounce or refusal."""
        info = dict(self.wait_info or {"by": self.by, "since": time.time(), "origin": "wait",
                                       "expires": None, "boot": self.job.get("boot")})
        now = time.time()
        info["waiting_on"] = _waiting_on(census) if census else info.get("waiting_on")
        info["checked_at"] = now
        if reason:
            info["reason"] = reason
        if bounce:
            info["bounces"] = int(info.get("bounces") or 0) + 1
        if bounce or refused:
            info["not_before"] = now + BOUNCE_BACKOFF
        return info

    def _waiting_again(self, info, bounce, tell, reason):
        """What a wait that went back says: its audit row, and at most one notice of each kind."""
        if self.fired:
            # Its fire was audited: an arm row after it is what tells a restart a wait is pending.
            log_action(None, "reboot_when_empty_arm", target=self.remote.name,
                       detail="back to waiting: %s" % (reason or ("a player joined" if bounce
                                                                  else "the host is not idle")),
                       actor=info.get("by") or self.by, remote=self.remote)
        if bounce and info["bounces"] == BOUNCE_NOTIFY_AT:
            notifications.notify("host_reboot", "Host reboot still waiting",
                                 "Players keep joining %s just before it reboots (%d times now); "
                                 "it keeps waiting for them to leave." % (
                                     _host_label(self.remote), info["bounces"]))
        if tell:
            notifications.notify("host_reboot", "Host reboot still waiting",
                                 "%s's queued reboot could not run: %s It keeps waiting and tries "
                                 "again every %d min; cancel it from the host's Power card." % (
                                     _host_label(self.remote), reason, BOUNCE_BACKOFF // 60))

    # ── countdown ──
    def _say_all(self, rows, text_for):
        """Say `text_for(gs)` in-game on each of these servers whose game can show a message."""
        ids = [b["id"] for b in rows or ()]
        if not ids:
            return
        for gs in GameServer.query.filter(GameServer.id.in_(ids)).all():
            if not _sm.moderation_caps(gs.game_type).get("say"):
                continue
            try:
                _sm.moderate(self.remote, gs.short_name, gs.game_type, "say", message=text_for(gs),
                             selfname=gs.lgsm_name)
            except Exception:  # noqa: BLE001 - a warning that failed must never stop the job
                _log.debug("in-game warning failed for %s", gs.id, exc_info=True)

    def _comes_back(self, census):
        """{server id: True} for the servers this reboot brings back, as the plan will decide it."""
        back = {"monitor", "panel"}
        if _sm.is_local_server(self.remote) and so.panel_starts_at_boot() is False:
            back.discard("panel")          # the panel starts those, and it will not be up
        probes = census.get("probes") or {}
        return {gs.id: classify(gs, probes.get(gs.id) or dict(_UNREAD))[0] in back
                for gs in GameServer.query.filter(GameServer.id.in_([w["id"] for w in self.warn])).all()}

    def _countdown(self, warn, census):
        """Warn the players in-game, then wait: 60 s, with reminders at 30 and 10."""
        self.warn = list(warn)
        back = self._comes_back(census)
        marks = list(COUNTDOWN)
        for i, left in enumerate(marks):
            self._phase("warning", left=left)

            def _text(gs, left=left):
                # "It will be back" only where it will: a queued stop or restoring turned off keeps
                # a server stopped, and players should not wait for it.
                return ("Server restarting in %d seconds: the host is rebooting.%s" % (
                    left, " It will be back in a few minutes." if back.get(gs.id) else ""))
            self._say_all(self.warn, _text)
            self._sleep(left - (marks[i + 1] if i + 1 < len(marks) else 0))

    # ── the plan ──
    def _make_plan(self, census):
        self._check_cancel()              # nothing touched yet: a cancel ends it here
        self._phase("stopping")
        rows = [gs for gs in GameServer.query.filter_by(remote_id=self.remote_id, installed=True).all()
                if gs.status not in ("installing", "configuring")]
        probes = census.get("probes") if not self.warn else None
        if probes is None:
            probes = _probe_rows(self.remote, rows)
        for gs in rows:
            p = probes.get(gs.id) or dict(_UNREAD)
            p = self._rearm_leftover(gs, p)
            owner, _why = classify(gs, p)
            if owner is None:
                continue
            self.entries.append(self._entry(gs, owner, p))
        self._commit_plan(rows)
        self._disarm_all()

    def _entry(self, gs, owner, probe):
        from panel.db.models import row_birth
        return {"id": gs.id, "born": row_birth(gs), "name": gs.name, "user": gs.short_name,
                "selfname": gs.lgsm_name, "game_type": gs.game_type, "owner": owner,
                "lock": probe.get("lock"), "stop": None, "aside": None,
                "stop_pending": bool(gs.stop_pending)}

    def _rearm_leftover(self, gs, probe):
        """A lock an interrupted plan left aside is put back first: LinuxGSM's own state comes first."""
        if probe.get("lock") != "none" or probe.get("aside") in (None, "none"):
            return probe
        armed = put_locks_back(self.remote, gs.short_name, [(gs.lgsm_name, "monitor")])
        log_action(None, "remote_reboot_rollback", target=self.remote.name, success=bool(armed),
                   detail="a lock left aside by an earlier plan put back: %s" % gs.name,
                   actor="system", remote=self.remote)
        return probe_server(self.remote, gs) if armed else probe

    def _commit_plan(self, rows):
        now = time.time()
        for gs in rows:
            e = next((x for x in self.entries if x["id"] == gs.id), None)
            if e is None:
                continue
            _set_rr(gs, self._record(e, now))
            _expected_offline[gs.id] = float("inf")
        db.session.commit()
        others = [gs.id for gs in rows if not any(x["id"] == gs.id for x in self.entries)]
        if others:
            _mon._mark_host_expected_offline(self.remote_id)
            for e in self.entries:
                _expected_offline[e["id"]] = float("inf")
        self._phase("stopping")

    def _record(self, e, now):
        return {"v": 1, "plan": self.job["plan"], "boot": self.job["boot"], "mid": self.job["mid"],
                "owner": e["owner"], "lock": e["lock"], "aside": None, "at": now, "sent": None,
                "by": self.by, "origin": self.job["origin"], "mode": self.job["mode"],
                "stop": None, "restore": "pending", "attempts": 0, "boot_seen": None,
                "queued": bool(e.get("stop_pending"))}

    def _disarm_all(self):
        for e in self.entries:
            if e.get("disarmed"):
                continue
            e["disarmed"] = True
            if e["owner"] == "panel" or e["lock"] not in ("monitoring", "legacy"):
                continue
            got = disarm(self.remote, e)
            if got in ("monitoring", "legacy"):
                e["aside"] = got
            elif got is None:
                # Not moved aside, and the stop is about to delete it: only the panel can bring
                # this one back now.
                e["owner"] = "panel" if e["owner"] == "monitor" else e["owner"]
            self._update_row(e, owner=e["owner"], aside=e["aside"])

    def _update_row(self, e, **fields):
        from panel.db.models import same_row
        gs = same_row(GameServer, e["id"], e["born"])
        d = rr(gs) if gs is not None else None
        if d is None:
            return False
        d.update(fields)
        _set_rr(gs, d)
        db.session.commit()
        return True

    # ── the stop phase ──
    def _stop_phase(self):
        """Stop every plan server: parallel across accounts, serial within one, verified by state."""
        self._phase("stopping", done=0, total=len(self.entries))
        self.bounce = False
        self.deadline = time.monotonic() + STOP_PHASE_CAP
        loaded = self._loaded_rows()
        groups = {}
        for e in self.entries:
            groups.setdefault(e["user"], []).append(e)
        if groups:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(STOP_WORKERS, len(groups))) as ex:
                list(ex.map(lambda grp: self._stop_group(grp, loaded), groups.values()))
        for e in self.entries:
            self._update_row(e, stop=e["stop"])
            if e["stop"] == "stopped" and e["stop_pending"]:
                self._clear_stop_pending(e)
        self._check_cancel()

    def _loaded_rows(self):
        """The plan's rows with their host loaded HERE: the pool's threads only read them."""
        ids = [e["id"] for e in self.entries] or [-1]
        loaded = {gs.id: gs for gs in GameServer.query.filter(GameServer.id.in_(ids)).all()}
        for gs in loaded.values():
            _loaded(_loaded(gs).remote)
        _loaded(self.remote)
        return loaded

    def _past_deadline(self):
        return self.deadline is not None and time.monotonic() > self.deadline

    def _stop_group(self, group, loaded):
        for e in group:
            if self.bounce or self._cancelled() or self._past_deadline():
                return
            if self.job["mode"] == "when_empty" and not self._still_empty(loaded.get(e["id"])):
                self.bounce = True
                return
            self._stop_one(e)
            done = sum(1 for x in self.entries if x.get("stop"))
            with _hr_lock:
                self.job["done"], self.job["total"] = done, len(self.entries)

    def _still_empty(self, gs):
        if gs is None:
            return True
        try:
            return _mon._server_slots(gs)[0] == 0
        except Exception:  # noqa: BLE001 - an unread count is not an empty server
            return False

    def _stop_one(self, e):
        budget = STOP_BUDGET_TELNET if e["game_type"] in _TELNET_STOP_GAMES else STOP_BUDGET
        try:
            _sm.run_as_game_user(self.remote, e["user"], "stop", timeout=budget,
                                 selfname=e["selfname"])
        except Exception:  # noqa: BLE001 - the state read below decides, never the call
            _log.debug("stop of %s raised", e["id"], exc_info=True)
        # The rc is not the outcome (a refused stop exits 0 with the server still up, a stop of a
        # stopped server exits 0 too): the session is.
        sess = probe_server(self.remote, e).get("session")
        e["stop"] = {0: "stopped", 1: "still_running"}.get(sess, "failed")

    def _clear_stop_pending(self, e):
        from panel.db.models import same_row
        gs = same_row(GameServer, e["id"], e["born"])
        if gs is not None and gs.stop_pending:
            gs.stop_pending = False
            db.session.commit()

    def _bounced(self):
        """A player joined just before their server's stop: undo, quietly, and go back to waiting.

        A Cancel in before this point already ended the job (_stop_phase raises it). One that lands
        during the rollback is seen by _back_to_waiting, which then does not put the wait back, and
        _on_cancel says what happened.
        """
        if not self.bounce:
            return False
        rollback(self.remote_id, "a player joined", wait=75, quiet=True)
        self.rolled_back = True
        self._back_to_waiting(None, bounce=True)
        return True

    def _rescan(self):
        """Once more, after the stops: anything running again (a monitor run, a cron) is stopped.

        Within what is left of the stop phase's budget: past it, a server found running is not
        stopped again but recorded as still running, and the shutdown ends it.
        """
        rows = [gs for gs in GameServer.query.filter_by(remote_id=self.remote_id, installed=True).all()
                if gs.status not in ("installing", "configuring")]
        probes = _probe_rows(self.remote, rows)
        known = {e["id"]: e for e in self.entries}
        for gs in rows:
            if (probes.get(gs.id) or {}).get("session") != 1:
                continue
            e = known.get(gs.id) or self._join_plan(gs, probes[gs.id])
            if e is None or e.get("stop") == "still_running":
                continue                  # not the plan's; or LinuxGSM refused its stop: the shutdown ends it
            self._restop(e)

    def _restop(self, e):
        """Stop again a server found running — within the stop phase's budget, else the shutdown ends it."""
        self._check_cancel()
        if self._past_deadline():
            e["stop"] = "still_running"
        else:
            self._stop_one(e)
        self._update_row(e, stop=e["stop"])

    def _join_plan(self, gs, probe):
        """A server found running that the plan does not hold: in the plan now, or None (not ours)."""
        owner, _why = classify(gs, probe)
        if owner is None:
            return None
        e = self._entry(gs, owner, probe)
        self.entries.append(e)
        _set_rr(gs, self._record(e, time.time()))
        _expected_offline[gs.id] = float("inf")
        db.session.commit()
        self._disarm_all()
        return e

    # ── send ──
    def _send(self):
        """Bookkeeping first, then the window, the locks back, and at once the reboot.

        `sent` is set under _hr_lock only while no Cancel is in: cancel() reads it under the same
        lock, so a Cancel is either seen here (and nothing is sent) or refused as too late.
        """
        now = time.time()
        with _hr_lock:
            cancelled = self.job.get("cancel")
            if not cancelled:
                self.job["sent"] = now
        if cancelled:
            raise _Cancelled()
        for e in self.entries:
            self._update_row(e, sent=now)
        _reboot_awaiting[self.remote_id] = {"sent": now, "back": None}
        self._audit_and_announce()
        self._phase("arming")
        reason = self._await_window()
        if reason is None:
            reason = self._rearm_and_reboot()
        if reason is not None:
            _reboot_awaiting.pop(self.remote_id, None)
            with _hr_lock:
                self.job["sent"] = None
            rollback(self.remote_id, reason, wait=75)
            return
        self._phase("rebooting")

    def _outcomes(self):
        words = []
        for e in self.entries:
            words.append("%s: %s, %s" % (e["name"], e.get("stop") or "not stopped",
                                         {"monitor": "back by Autostart", "panel": "started by the panel",
                                          "none": "stays stopped"}.get(e["owner"], e["owner"])))
        return "; ".join(words)

    def _audit_and_announce(self):
        n = sum(1 for e in self.entries if e.get("stop") == "stopped")
        detail = "%s; %d player(s) disconnected; %s" % (self.job["mode"], self.disconnected,
                                                       self._outcomes() or "no game servers running")
        log_action(self._user(), "remote_reboot", target=self.remote.name, detail=detail,
                   actor=None if self.actor_id else self.by, remote=self.remote)
        notifications.notify("host_reboot", "Rebooting %s" % _host_label(self.remote),
                             self._announce_text(n))
        if _sm.is_local_server(self.remote):
            notifications.flush(timeout=10)

    def _announce_text(self, n):
        """The 'Rebooting X' notice: what was stopped, and what comes back — true of every plan."""
        if not self.entries:
            return "No game servers were running, so none were stopped."
        back = sum(1 for e in self.entries if e["owner"] in ("monitor", "panel"))
        stay = len(self.entries) - back
        text = "Stopped %d game server%s cleanly (%d player%s disconnected)." % (
            n, "" if n == 1 else "s", self.disconnected, "" if self.disconnected == 1 else "s")
        if back:
            text += " %d come%s back after the reboot." % (back, "s" if back == 1 else "")
        if stay:
            text += (" %d stay%s stopped (a queued stop, or no Autostart with restoring turned off "
                     "in Settings)." % (stay, "s" if stay == 1 else ""))
        return text

    def _accounts(self):
        """{account: [entries]} whose locks were moved aside: the ones put back before the reboot."""
        acc = {}
        for e in self.entries:
            if e["owner"] in ("monitor", "none") and e.get("aside"):
                acc.setdefault(e["user"], []).append(e)
        return acc

    def _await_window(self):
        """Wait (at most ARM_WAIT) for the moment the reboot may go; None when it is open.

        No LinuxGSM command in flight for ANY plan server (an update or a backup a cron started on
        one the panel brings back would be cut off as surely as one on an Autostart server), and,
        for the accounts whose locks go back, a second of the minute no monitor run can see.
        """
        users = {}
        for e in self.entries:
            users.setdefault(e["user"], []).append(e["selfname"])
        if not users:
            return None
        aside = self._accounts()
        # The accounts with nothing to put back are read first: the seconds that count are the
        # ones between an account's read and its lock going back, and those come last.
        order = sorted(users, key=lambda u: u in aside)
        end = time.monotonic() + ARM_WAIT
        busy = False
        # A shell per account runs between this read and the reboot, so the later the window
        # closes for the last of them, the less of it is left: two seconds an account.
        window = (ARM_WINDOW[0], max(ARM_WINDOW[0] + 5, ARM_WINDOW[1] - 2 * len(aside)))
        while time.monotonic() < end:
            seen = {u: window_probe(self.remote, u, users[u]) for u in order}
            busy = any(s.get("inflight") for s in seen.values())
            if _quiet_now(seen, aside, window):
                return None
            time.sleep(2)
        return ("a LinuxGSM command was running for one of its servers" if busy
                else "the host did not answer in time")

    def _rearm_and_reboot(self):
        """Put the locks back and reboot, in that order and nothing in between: None, or why not."""
        for user, es in self._accounts().items():
            done = put_locks_back(self.remote, user, [(e["selfname"], e["owner"]) for e in es])
            missing = [e["id"] for e in es if e["selfname"] not in done]
            if missing:
                _log.warning("reboot: the locks of %s could not be confirmed back", missing)
        return send_reboot(self.remote)


def send_reboot(remote):
    """The reboot command itself: None when it was sent, else why it was not, as a sentence.

    `reboot-delayed`, so the command returns before the host goes down: on the panel host a 2 s
    systemd timer (the helper), on a remote `( sleep 2 ; reboot ) &`. A positive exit status is the
    host refusing (sudo, an old helper). A connection that drops once the command is under way —
    paramiko's ConnectionError marked `command_started`, the other transports' -1 — is what a reboot
    looks like, so it counts as sent; a connection that never opened (refused, the login rejected,
    a host key that does not match) sent nothing, and is a refusal the job rolls back at once.
    """
    try:
        out, err, rc = _sm.run_privileged(remote, "reboot-delayed", [], timeout=15, merge_stderr=False)
    except Exception as exc:  # noqa: BLE001 - which one decides: see the docstring
        if getattr(exc, "command_started", False):
            return None
        return "the panel could not connect to send the reboot (%s)" % (
            (str(exc).strip()[:160]) or type(exc).__name__)
    if isinstance(rc, int) and rc > 0:
        return "the host refused the reboot: %s" % ((err or out or "").strip()[:160] or rc)
    return None


def _window_open(seen, window):
    """Whether every account's read is inside `window` with nothing of LinuxGSM's in flight."""
    return all(in_window(s.get("sec"), window) and s.get("inflight") == 0 for s in seen)


# The seconds of the minute in which a read of an account with no lock to put back counts: one made
# after second 2 sees whatever cron started at :00, and before second 50 leaves the reboot (sent
# straight after) inside the same minute, so no later :00 start slips between the read and it.
QUIET_SECONDS = (2, 50)


def _quiet_now(seen, aside, window):
    """Whether the reboot may go now.

    Every account read (`seen`: {account: read}) has nothing of LinuxGSM's in flight, the accounts
    whose locks go back (`aside`) were read inside `window`, and the others inside QUIET_SECONDS.
    """
    return _window_open([r for u, r in seen.items() if u in aside], window) and _window_open(
        [r for u, r in seen.items() if u not in aside], QUIET_SECONDS)


def window_probe(remote, user, selfnames):
    """Read one account's window: {sec, boot, inflight}, None values when it did not answer.

    The second of the host's minute, its boot id, and how many LinuxGSM commands are running for
    any of `selfnames`.
    """
    pats = [_cmd_pattern(s, _INFLIGHT_CMDS) for s in selfnames if _sm.game_idents_ok(user, s)]
    if not pats:
        return {"sec": None, "boot": None, "inflight": None}
    sh = ("n=0; for p in %s; do c=$(pgrep -u \"$(id -un)\" -fc \"$p\"); n=$((n + c)); done; "
          'echo "INFLIGHT=$n"; echo "SEC=$(date +%%S)"; echo "BOOT=$(cat /proc/sys/kernel/random/boot_id)"; '
          "echo WINDOW_OK" % " ".join(_q(p) for p in pats))
    out = _game_shell(remote, user, selfnames[0], sh)
    if "WINDOW_OK" not in out:
        return {"sec": None, "boot": None, "inflight": None}
    vals = dict(ln.split("=", 1) for ln in out.splitlines() if "=" in ln)
    return {"sec": _int_or_none(vals.get("SEC")), "boot": vals.get("BOOT"),
            "inflight": _int_or_none(vals.get("INFLIGHT"))}


def _waiting_on(census):
    return {"busy": [{"name": b["name"], "players": b["players"]} for b in census.get("busy", ())],
            "unknown": [{"name": u["name"], "reason": u["reason"]} for u in census.get("unknown", ())],
            "blockers": list(census.get("blockers", ()))}


# ── Rollback and restore: the restore worker's pass, also what the job uses to undo itself ──────
def rollback(remote_id, reason, wait=75, quiet=False):
    """Undo a plan whose reboot did not happen: every server back as it was before the plan.

    Monitor-owned servers get their lock back (LinuxGSM's monitor restarts them within 5 min),
    panel-owned ones a SAFE START now, and 'none' ones lose the aside file. NEVER re-issues a
    reboot. Runs passes for up to `wait` seconds (a start waits for its window); whatever is left
    is the restore worker's.
    """
    for gs in plan_rows(remote_id):
        d = rr(gs)
        d.update(act="now", reason=reason, quiet=bool(quiet))
        _set_rr(gs, d)
    db.session.commit()
    _reboot_awaiting.pop(remote_id, None)
    remote = db.session.get(RemoteServer, remote_id)
    if remote is None:
        return
    end = time.monotonic() + max(0, wait)
    while True:
        rows = plan_rows(remote_id)
        if not rows:
            return
        restore_host(remote, rows)
        if time.monotonic() >= end:
            return
        time.sleep(5)


def restore_host(remote, rows, now=None):
    """One restore step for one host's plan rows. True while it wants the fast tick."""
    now = time.time() if now is None else now
    recs = _records(rows)
    if not recs:
        return False
    if any(d.get("act") == "now" for _gs, d in recs):
        _act(remote, recs, now, rollback_=True)
        return True
    ident = _sm.hosts.host_boot_identity(remote)
    if ident is None:
        return _host_silent(remote, recs, recs[0][1], now)
    return _by_boot(remote, recs, ident, now)


def _records(rows):
    recs = [(gs, rr(gs)) for gs in rows]
    return [(gs, d) for gs, d in recs if d]


def _by_boot(remote, recs, ident, now):
    """The host answered: the same machine on the same boot, a new boot, or another machine."""
    meta = recs[0][1]
    if ident["mid"] != meta.get("mid"):
        _clear(remote, recs, "a different machine now answers at %s's address, so nothing was "
                             "started there" % _host_label(remote))
        return False
    if ident["boot"] == meta.get("boot"):
        return _same_boot(remote, recs, meta, ident, now)
    return _new_boot(remote, recs, meta, ident, now)


def _mark_all(recs, **fields):
    for gs, d in recs:
        d.update(fields)
        _set_rr(gs, d)
    db.session.commit()


def _host_silent(remote, recs, meta, now):
    """The host does not answer: keep the plan, say so once after LATE_NOTICE_AFTER."""
    if now - (meta.get("at") or now) > STALE_PLAN:
        _clear(remote, recs, "%s has not answered for a week, so its servers' restore was "
                             "dropped" % _host_label(remote))
        return False
    sent = meta.get("sent")
    if sent and now - sent >= LATE_NOTICE_AFTER and not meta.get("late"):
        _mark_all(recs, late=True)
        notifications.notify("host_reboot", "Host not back yet",
                             "%s hasn't come back after %d min; its %d server%s come back when it "
                             "does." % (_host_label(remote), (now - sent) // 60, len(recs),
                                        "" if len(recs) == 1 else "s"))
    return bool(sent)


def _same_boot(remote, recs, meta, ident, now):
    """Still the boot the plan was made on: the reboot is pending, or it did not happen."""
    sent = meta.get("sent")
    if now - (sent or meta.get("at") or now) > STALE_SENT:
        # A plan from a day ago that never rebooted: a database restored over this one, not a
        # reboot in progress. Nothing is started from it.
        _clear(remote, recs, "a reboot plan from more than a day ago was found and dropped",
               notify=False)
        return False
    if sent is None:
        reason = "the panel restarted before the reboot was sent"
    elif ident.get("state") == "stopping":
        return True
    elif now - sent >= DID_NOT_HAPPEN_AFTER:
        reason = "the host is still on the same boot %d min after the reboot was sent" % (
            (now - sent) // 60)
    else:
        return True
    _mark_all(recs, act="now", reason=reason)
    _reboot_awaiting.pop(remote.id, None)
    _act(remote, recs, now, rollback_=True)
    return True


def _new_boot(remote, recs, meta, ident, now):
    """The host rebooted: once it has settled, bring back what the plan says."""
    if not meta.get("boot_seen"):
        sent = meta.get("sent") or now
        _mark_all(recs, boot_seen=max(sent, now - float(ident.get("uptime") or 0)))
        _reboot_awaiting[remote.id] = {"sent": sent, "back": now}
    up = float(ident.get("uptime") or 0)
    if not ((up >= SETTLE_UPTIME and ident.get("state") != "starting") or up >= SETTLE_UPTIME_MAX):
        return True
    _act(remote, recs, now, rollback_=False)
    return True


def _act(remote, recs, now, rollback_):
    """Run each pending row's restore step; when none is pending any more, finish the plan."""
    for gs, d in recs:
        if d.get("restore") != "pending":
            continue
        before = dict(d)
        res = _act_one(remote, gs, d, now, rollback_)
        if res is not None:
            d["restore"], d["result"] = res
        if d != before:
            _set_rr(gs, d)
            db.session.commit()
    if all(d.get("restore") != "pending" for _gs, d in recs):
        _finish(remote, recs, now, rollback_)


def _act_one(remote, gs, d, now, rollback_):
    """(restore, result) once a row is resolved, None while it is not yet."""
    if rollback_ and d.get("stop") != "stopped":
        kept = _act_kept(remote, gs)
        if kept is not False:
            return kept
    owner = d.get("owner")
    if owner == "monitor":
        return _act_monitor(remote, gs, d, now, rollback_)
    if owner == "panel":
        return _act_panel(remote, gs, d, now, rollback_)
    # 'none': stopped, and its lock (moved aside) dropped, as an operator's stop drops it.
    put_locks_back(remote, gs.short_name, [(gs.lgsm_name, "none")])
    if rollback_ and d.get("queued") is False:
        # The reboot it was to stay stopped through never happened, so it is put back as it was:
        # running. Only a queued stop stays stopped (it was due). A plan recorded before "queued"
        # existed keeps the old answer.
        return _act_panel(remote, gs, d, now, rollback_)
    return "done", "stopped"


def _act_kept(remote, gs):
    """A rollback's row whose stop never took: ("done", "kept"), False, or None.

    ("done", "kept") when it is still running, False when it is not (the owner's own step decides
    then), None while it cannot be read. The plan was undone before its stop ran (a Cancel, a bounce, the stop budget), or LinuxGSM
    refused the stop: the server never went down. Its lock, if the plan moved it aside, goes back
    where it was, and nothing else is done to it — for every owner. A 'none' row's aside file used
    to be deleted here, which left a running server LinuxGSM's monitor no longer watched, and the
    summary said it "stayed stopped".
    """
    p = probe_server(remote, gs)
    if p.get("session") is None:
        return None
    if p.get("session") != 1:
        return False
    if p.get("aside") not in (None, "none") and gs.lgsm_name not in put_locks_back(
            remote, gs.short_name, [(gs.lgsm_name, "monitor")]):
        return None
    return "done", "kept"


def _act_monitor(remote, gs, d, now, rollback_):
    """A server LinuxGSM's monitor brings back: the panel only makes sure its lock is in place."""
    p = probe_server(remote, gs)
    if p.get("session") is None:
        return None
    if p.get("lock") == "none":
        return _act_unarmed(remote, gs, d, now, rollback_, p)
    if rollback_ or p.get("session") == 1:
        return "done", "autostart"
    if now - (d.get("boot_seen") or now) >= NOT_BACK_AFTER:
        return "failed", ("LinuxGSM's monitor has not brought it back; it keeps trying every 5 "
                          "min (see the server's LinuxGSM log)")
    return None


def _act_unarmed(remote, gs, d, now, rollback_, p):
    """A monitor-owned server found with no lock in place."""
    if p.get("aside") not in (None, "none"):
        # Still aside: the reboot did not happen (a rollback), or the host went down between the
        # stop and the re-arm. Put it back now — no window this time: no shutdown is coming, so a
        # monitor run that reads it and restarts the server does exactly what is wanted.
        if gs.lgsm_name not in put_locks_back(remote, gs.short_name, [(gs.lgsm_name, "monitor")]):
            return None
        return ("done", "autostart") if rollback_ or p.get("session") == 1 else None
    if p.get("session") == 1:
        return "done", "autostart"
    # No lock at all: the monitor cannot bring it back, so the panel does.
    return _act_panel(remote, gs, d, now, rollback_)


def _act_panel(remote, gs, d, now, rollback_):
    """A server the panel brings back: SAFE START, three tries at least a minute apart."""
    if now - (d.get("last_try") or 0) < START_RETRY_GAP:
        return None
    if not rollback_ and not _scope_ready(remote, d, now):
        return None
    outcome, detail = safe_start(remote, gs)
    if outcome == "wait":
        return None
    if outcome in ("started", "running"):
        _after_start(remote, gs)
        return "done", "panel"
    d["attempts"] = int(d.get("attempts") or 0) + 1
    d["last_try"] = now
    d["why"] = detail
    if d["attempts"] >= START_ATTEMPTS:
        return "failed", detail
    return None


def _scope_ready(remote, d, now):
    """On a per-user panel host without the helper: wait (up to 120 s) for a scope to start in.

    user_scope_argv() believes a failed probe for ten minutes, and right after a boot the panel can
    ask before the user manager answers: a game started then lands in the panel's own cgroup, and
    the next panel stop ends it.
    """
    if not _sm.is_local_server(remote) or _sm.helper_present():
        return True
    if not os.path.exists(_sm._core._USER_UNIT):
        return True
    # Asked afresh each time: the cached answer is the very failure this waits out.
    _sm._core.reset_user_scope_probe()
    if _sm._core.user_scope_argv():
        return True
    return now - (d.get("boot_seen") or now) >= 120


def _after_start(remote, gs):
    """What a panel start's bookkeeping does (server_detail._after_power_action)."""
    try:
        _sm._invalidate_port_scan(remote.id)
        if gs.restart_pending:
            gs.restart_pending = False
            db.session.commit()
        _sm.set_game_priority(remote, gs.short_name)
    except Exception:  # noqa: BLE001 - bookkeeping; the server is running
        db.session.rollback()
        _log.debug("after-start bookkeeping failed for %s", gs.id, exc_info=True)


def _tally(recs):
    results = [d.get("result") for _g, d in recs]
    failed = [(gs.name, d.get("result")) for gs, d in recs if d.get("restore") == "failed"]
    return (results.count("autostart"), results.count("panel"), results.count("stopped"),
            results.count("kept"), failed)


def _summary(remote, recs, now, rollback_):
    auto, panel, stayed, kept, failed = _tally(recs)
    want = auto + panel + len(failed)
    if rollback_:
        text = ("Reboot of %s did not happen (%s): %d server%s coming back. %d started now, %d by "
                "Autostart within 5 min." % (_host_label(remote), recs[0][1].get("reason") or "?",
                                             want, "" if want == 1 else "s", panel, auto))
    else:
        mins = max(0, int((now - (recs[0][1].get("sent") or now)) // 60))
        text = ("%s is back after %d min: %d/%d running again (%d by Autostart, %d started by the "
                "panel)." % (_host_label(remote), mins, auto + panel, want, auto, panel))
    if stayed:
        # They were RUNNING before the reboot (a stopped server is never in a plan): not "as before".
        text += (" %d stayed stopped, as planned (a queued stop, or no Autostart with restoring "
                 "turned off)." % stayed)
    if kept:
        # Only in a rollback: the plan was undone before its stop took, so it never stopped.
        text += " %d kept running (%s not stopped)." % (kept, "it was" if kept == 1 else "they were")
    for name, why in failed:
        text += " %s didn't come back: %s." % (name, why)
    return text, not failed


def _finish(remote, recs, now, rollback_):
    """Every row resolved: one summary, the audit row, and the rows cleared."""
    text, ok = _summary(remote, recs, now, rollback_)
    quiet = any(d.get("quiet") for _g, d in recs)
    for gs, d in recs:
        gs.reboot_restore = None
        _expected_offline[gs.id] = now + GRACE_AFTER_CLEAR
        if d.get("restore") == "failed":
            _monitor_state["servers"][gs.id] = False   # the summary said so; no "went offline" too
    db.session.commit()
    log_action(None, "remote_reboot_rollback" if rollback_ else "remote_reboot_restore",
               target=remote.name, detail=text, success=ok, actor="system", remote=remote)
    _last_result[remote.id] = {"at": now, "text": text, "ok": ok}
    if not quiet:
        notifications.notify("host_reboot", "Host reboot", text)
    with _hr_lock:
        job = _host_reboots.get(remote.id)
        if job and job.get("phase") == "rebooting":
            _host_reboots.pop(remote.id, None)


def _clear(remote, recs, why, notify=True):
    """Drop a plan without acting on it."""
    now = time.time()
    for gs, _d in recs:
        gs.reboot_restore = None
        _expected_offline[gs.id] = now + GRACE_AFTER_CLEAR
    db.session.commit()
    _reboot_awaiting.pop(remote.id, None)
    log_action(None, "remote_reboot_restore", target=remote.name, detail=why, success=False,
               actor="system", remote=remote)
    _last_result[remote.id] = {"at": now, "text": why, "ok": False}
    if notify:
        notifications.notify("host_reboot", "Host reboot", why[:1].upper() + why[1:] + ".")
    with _hr_lock:
        job = _host_reboots.get(remote.id)
        if job and job.get("phase") == "rebooting":
            _host_reboots.pop(remote.id, None)


def exclude_row(gs, actor, what, origin=None):
    """An operator acted on a server while its host's reboot plan holds it: the operator wins.

    Its row leaves the plan (audited), so the restore never starts or stops it behind their back.
    `origin` names a caller with no panel account (a chat bot) for the audit row.
    """
    if rr(gs) is None:
        return False
    gs.reboot_restore = None
    _expected_offline[gs.id] = time.time() + GRACE_AFTER_CLEAR
    db.session.commit()
    log_action(actor, "remote_reboot_exclude", target=gs.name,
               detail="%s by an operator: left out of the reboot's restore" % what,
               actor=origin, server=gs, remote=gs.remote)
    return True


def _bare_job_step(remote, job, now):
    """A host rebooted with no game servers to bring back: just watch for it to return."""
    ident = _sm.hosts.host_boot_identity(remote)
    sent = job.get("sent") or now
    text = (_bare_answered(remote, job, ident, now, sent) if ident is not None
            else _bare_silent(remote, now, sent))
    if text:
        _last_result[remote.id] = {"at": now, "text": text, "ok": "did not" not in text}
        notifications.notify("host_reboot", "Host reboot", text)
        with _hr_lock:
            _host_reboots.pop(remote.id, None)


def _bare_answered(remote, job, ident, now, sent):
    if job.get("boot") and ident["boot"] != job["boot"]:
        _reboot_awaiting[remote.id] = {"sent": sent, "back": now}
        return "%s is back after %d min (no game servers were running)." % (
            _host_label(remote), max(0, int((now - sent) // 60)))
    if now - sent >= DID_NOT_HAPPEN_AFTER and ident.get("state") != "stopping":
        _reboot_awaiting.pop(remote.id, None)
        return "Reboot of %s did not happen: it is still on the same boot." % _host_label(remote)
    return None


def _bare_silent(remote, now, sent):
    with _hr_lock:
        job = _host_reboots.get(remote.id) or {}
        late = now - sent >= LATE_NOTICE_AFTER and not job.get("late")
        if late:
            job["late"] = True
    if late:
        notifications.notify("host_reboot", "Host not back yet",
                             "%s hasn't come back after %d min." % (_host_label(remote),
                                                                    (now - sent) // 60))
    if now - sent > STALE_SENT:
        # The hold on its unreachable/recovered alerts ends with this notice: without the pop it
        # held them for as long as the panel ran, so its next real outage would never alert.
        _reboot_awaiting.pop(remote.id, None)
        return "%s has not come back after a day." % _host_label(remote)
    return None


def run_restore_pass(app, now=None):
    """One tick of the restore worker; returns how long to sleep before the next."""
    now = time.time() if now is None else now
    with app.test_request_context():
        by_host = _rows_by_host()
        busy = _restore_hosts(by_host, now)
        busy = _watch_bare_jobs(by_host, now) or busy
        _forget_old_awaiting(now)
    return BUSY_TICK if busy else IDLE_TICK


def _rows_by_host():
    by_host = {}
    for gs in GameServer.query.filter(GameServer.reboot_restore.isnot(None)).all():
        if rr(gs):
            by_host.setdefault(gs.remote_id, []).append(gs)
    return by_host


def _restore_hosts(by_host, now):
    busy = False
    for rid, rows in by_host.items():
        job = job_of(rid)
        if job and job.get("phase") != "rebooting":
            continue                  # the job in this process still owns it
        remote = db.session.get(RemoteServer, rid)
        if remote is not None and restore_host(remote, rows, now):
            busy = True
    return busy


def _watch_bare_jobs(by_host, now):
    rids = [r for r, j in _jobs_snapshot() if j.get("phase") == "rebooting" and r not in by_host]
    for rid in rids:
        remote = db.session.get(RemoteServer, rid)
        if remote is not None:
            _bare_job_step(remote, job_of(rid) or {}, now)
    return bool(rids)


def _jobs_snapshot():
    with _hr_lock:
        return [(rid, dict(j)) for rid, j in _host_reboots.items()]


def _forget_old_awaiting(now):
    for rid, ent in list(_reboot_awaiting.items()):
        if ent.get("back") and now - ent["back"] > 3600:
            _reboot_awaiting.pop(rid, None)


def host_reboot_worker(app):
    """The supervised restore loop: every 15 s while a host is coming back, else every 60 s.

    Its first pass is BUSY_TICK after the start: resume_reboot_state has already held the alerts,
    and on the panel's own host this is the pass that brings the servers back.
    """
    runtime_stats.loop_started("host-reboot", BUSY_TICK)
    time.sleep(BUSY_TICK)
    while True:
        try:
            t0 = time.time()
            wait = run_restore_pass(app)
            runtime_stats.beat("host-reboot", IDLE_TICK, time.time() - t0)
        except Exception:  # noqa: BLE001 - one bad pass must not end the loop
            runtime_stats.bump("loopfail", "host-reboot")
            _log.debug("host-reboot pass failed", exc_info=True)
            wait = IDLE_TICK
        time.sleep(wait)


# ── The wait for empty: supervised, 60 s tick ───────────────────────────────────────────────────
def wait_pass(app, now=None):
    """One tick of 'reboot when everyone has left' for every host that is waiting."""
    with _rwe_lock:
        pending = list(_reboot_when_empty.keys())
    if not pending:
        return
    with app.test_request_context():
        for rid in pending:
            try:
                _wait_one(app, rid, time.time() if now is None else now)
            except Exception:  # noqa: BLE001 - one host must not stop the others
                db.session.rollback()
                _log.debug("reboot-when-empty tick failed for remote %s", rid, exc_info=True)


def _wait_one(app, rid, now):
    """One host's wait: expire it, drop it, leave it, or (idle) fire it."""
    info, remote = _wait_entry(rid)
    if remote is None:
        return
    if info.get("expires") and now >= info["expires"]:
        _expire_wait(remote, info)
        return
    if not _wait_may_look(remote, info, now):
        return
    ident = _sm.hosts.host_boot_identity(remote)
    if _rebooted_since(ident, info):
        _drop_wait(remote, "the host rebooted outside the panel")
        return
    census = host_player_state(remote)
    _note_census(rid, info, census, ident, now)
    if census["state"] == "idle":
        _fire_wait(app, remote)


def _wait_entry(rid):
    """(the wait's entry, its host row): (_, None) when there is no wait, or no host any more."""
    with _rwe_lock:
        info = dict(_reboot_when_empty.get(rid) or {})
    remote = db.session.get(RemoteServer, rid) if info else None
    if info and remote is None:
        with _rwe_lock:
            _reboot_when_empty.pop(rid, None)
    return info, remote


def _rebooted_since(ident, info):
    return bool(ident and info.get("boot") and ident["boot"] != info["boot"])


def _wait_may_look(remote, info, now):
    """Not before a bounce's back-off, not while a job runs, and never on a host that is not answering."""
    if now < (info.get("not_before") or 0) or job_of(remote.id):
        return False
    return bool(_mon._host_reachable(remote))


def _unknown_since(info, census, now):
    if census["state"] != "unknown":
        return None
    return info.get("unknown_since") or now


def _note_census(rid, info, census, ident, now):
    unknown_since = _unknown_since(info, census, now)
    remind = (unknown_since is not None and now - unknown_since >= UNKNOWN_REMIND_AFTER
              and not info.get("reminded"))
    with _rwe_lock:
        cur = _reboot_when_empty.get(rid)
        if cur is None:
            return
        cur.update(waiting_on=_waiting_on(census), checked_at=now, unknown_since=unknown_since)
        if ident and not cur.get("boot"):
            cur["boot"] = ident["boot"]
        if remind:
            cur["reminded"] = True
    if remind:
        names = ", ".join(u["name"] for u in census["unknown"][:4]) or "a server"
        notifications.notify("host_reboot", "Reboot still waiting",
                             "Still waiting to reboot %s: %s's player count can't be read. Stop it, "
                             "or reboot now from the host's Power card." % (
                                 _host_label(db.session.get(RemoteServer, rid)), names))


def _fire_wait(app, remote):
    """The host is idle: hand its wait to a clean-reboot job (start_clean_reboot from_wait).

    The hand-over is the COMMIT POINT: the census above took tens of seconds, and an operator can
    cancel (or Reboot now can supersede) the wait in that window — then there is nothing to fire.
    The fire is audited and announced by the job, once it has passed its own checks: a job that
    finds the host busy, or cannot reboot it, puts the wait back having said nothing.
    """
    start_clean_reboot(remote, None, "wait", "when_empty", app=app, from_wait=True)


def _expire_wait(remote, info):
    with _rwe_lock:
        cur = _reboot_when_empty.get(remote.id)
        if cur is None or cur.get("since") != info.get("since"):
            return
        _reboot_when_empty.pop(remote.id, None)
    what = _still_on(info.get("waiting_on") or {})
    hours = max(1, int(((info.get("expires") or 0) - (info.get("since") or 0)) // 3600))
    log_action(None, "reboot_when_empty_expire", target=remote.name, detail=what or "",
               actor=info.get("by") or "system", remote=remote)
    notifications.notify("host_reboot", "Gave up waiting to reboot",
                         "Gave up waiting to reboot %s after %d h%s" % (
                             _host_label(remote), hours, (": " + what + ".") if what else "."))


def _still_on(on):
    """Say what a wait was still waiting on, as "GMod (3 players), Factorio (count unknown)"."""
    parts = ["%s (%d player%s)" % (b["name"], b["players"], "" if b["players"] == 1 else "s")
             for b in on.get("busy", ())]
    parts += ["%s (count unknown)" % u["name"] for u in on.get("unknown", ())]
    return ", ".join(parts)


def _drop_wait(remote, why):
    with _rwe_lock:
        info = _reboot_when_empty.pop(remote.id, None)
    if info is None:
        return
    log_action(None, "reboot_when_empty_drop", target=remote.name, detail=why,
               actor=info.get("by") or "system", remote=remote)


def reboot_when_empty_watch(app):
    """The supervised wait loop (60 s tick). Its runtime_stats name is the one the debug report reads."""
    runtime_stats.loop_started("reboot-when-empty", WAIT_TICK)
    while True:
        time.sleep(WAIT_TICK)
        runtime_stats.beat("reboot-when-empty", WAIT_TICK)
        try:
            wait_pass(app)
        except Exception:  # noqa: BLE001
            runtime_stats.bump("loopfail", "reboot-when-empty")
            _log.debug("reboot-when-empty pass failed", exc_info=True)


# ── Startup ─────────────────────────────────────────────────────────────────────────────────────
def resume_reboot_state(app):
    """At startup, BEFORE the monitor runs: hold the alerts of every server a plan still holds.

    Synchronous on purpose: the monitor's first pass would otherwise read a server the reboot took
    down as "went offline unexpectedly". The restore worker does the rest on its first tick.
    """
    with app.app_context():
        for gs in GameServer.query.filter(GameServer.reboot_restore.isnot(None)).all():
            d = rr(gs)
            if not d:
                continue
            _expected_offline[gs.id] = float("inf")
            if d.get("sent") and not d.get("boot_seen"):
                _reboot_awaiting[gs.remote_id] = {"sent": d["sent"], "back": None}


_WAIT_ACTIONS = ("reboot_when_empty_arm", "reboot_when_empty_cancel", "reboot_when_empty_fire",
                 "reboot_when_empty_drop", "reboot_when_empty_expire", "remote_reboot")


def announce_dropped_waits(app):
    """Tell the operator about every 'reboot when empty' this restart dropped.

    The wait lives in memory, so a panel restart (an update, a crash) ends it — on purpose: no
    surprise reboot survives a restart. It used to end silently. A host whose newest wait-related
    audit row is an arm had one pending; each gets a notification and a reboot_when_empty_drop row.
    """
    from datetime import timedelta
    from panel.core.clock import utcnow
    hours = wait_max_hours() or 24 * 7
    with app.test_request_context():
        since = utcnow() - timedelta(hours=hours)
        newest = {}
        for a in (AuditLog.query.filter(AuditLog.action.in_(_WAIT_ACTIONS),
                                        AuditLog.remote_id.isnot(None),
                                        AuditLog.timestamp >= since)
                  .order_by(AuditLog.id).all()):
            newest[a.remote_id] = a
        for rid, a in newest.items():
            if a.action != "reboot_when_empty_arm":
                continue
            remote = db.session.get(RemoteServer, rid)
            if remote is None:
                continue
            log_action(None, "reboot_when_empty_drop", target=remote.name,
                       detail="the panel restarted", actor=a.username or "system", remote=remote)
            notifications.notify("host_reboot", "Reboot wait cancelled",
                                 "The panel restarted, so the pending 'reboot when everyone has "
                                 "left' for %s was cancelled. Ask again from its Power card if you "
                                 "still want it." % _host_label(remote))
