"""Alerts for the bans, temporary bans and kicks a server's B3 add-on writes to its events.jsonl.

B3 (addons.B3_COMMIT) appends one JSON line (schema 1) per ban, tempban, unban, kick, warning, admin
command and control-socket request to Data/events.jsonl, mode 0640, and renames it events.jsonl.1 at
events_max_size (1 MB by default, one copy kept). The monitor's sweep (services/monitoring.py, once a
minute) reads what was added since its last look, for each server whose B3 card has the alerts switch
on (GameServer.b3_alerts, off by default), on a host the sweep found reachable: one read as the game
account per server, nothing for the others.

WHERE IT LEFT OFF. Per server, the file's inode and the offset after the last whole line read. The
same inode, at least that long: read on from the offset. Another inode: the file was rotated, so the
rest of events.jsonl.1 (when its inode is the one read before) and then the new file from its start.
The same inode but shorter: it was cut, read from its start. The first look after the switch is turned
on, or after the panel starts, only notes where the file ends (no alert for what B3 wrote before). At
most READ_MAX bytes a file per look; a partial last line waits for the next look.

PERSONAL DATA. A line names the player and the admin (B3 writes no IP address or GUID). Names reach
only the alert channels the panel's admins set up in Settings -> Notifications, with the "B3 penalties"
event on there, and only when they turned on "Include details" (chat_privacy: b3_penalty is one of its
PERSONAL_EVENTS); otherwise the alert says what happened and where, without names. Nothing here writes
a name or a reason to the panel's own log (Logging Cheat Sheet, "Data to exclude").
"""
import base64
import json
import logging
import shlex
import threading
import unicodedata

from panel.services import addons as _ad

_log = logging.getLogger("panel.b3_events")

EVENT = "b3_penalty"                   # notifications.EVENTS key
KINDS = ("ban", "tempban", "kick")     # the lines that raise an alert
READ_MAX = 65536
FOLD_AT = 3                            # more alerts than this from one server in one look: one summary
_NAME_MAX = 40
_REASON_MAX = 100
_STATE = {}                            # server id -> (inode text, offset)
_LOCK = threading.Lock()
_WORDS = {"ban": ("B3 banned a player on {server}", "{target} was banned by {admin}"),
          "tempban": ("B3 temporarily banned a player on {server}",
                      "{target} was banned for {minutes} minutes by {admin}"),
          "kick": ("B3 kicked a player on {server}", "{target} was kicked by {admin}")}


def forget(gs_id):
    """Drop where server `gs_id`'s file was left off: the next look only notes where it ends."""
    with _LOCK:
        _STATE.pop(gs_id, None)


def read_sh(user, state):
    """Shell, as the account, printing st=<inode> <size> and, after a first look, what was added (old.b64= new.b64=)."""
    f = shlex.quote("%s/Data/events.jsonl" % _ad.addon_dir(user, _ad.B3))
    head = "s=$(stat -c '%%i %%s' -- %s 2>/dev/null); echo \"st=$s\"; " % f
    if state is None:
        return head
    ino, off = shlex.quote(state[0]), int(state[1])
    return (head + "set -- $s; if [ \"${1:-}\" = %s ] && [ \"${2:-0}\" -ge %d ]; then "
            "echo \"new.b64=$(tail -c +%d %s | head -c %d | base64 -w0)\"; "
            "elif [ -n \"${1:-}\" ]; then "
            "if [ \"$(stat -c %%i -- %s.1 2>/dev/null)\" = %s ]; then "
            "echo \"old.b64=$(tail -c +%d %s.1 | head -c %d | base64 -w0)\"; fi; "
            "echo \"new.b64=$(head -c %d %s | base64 -w0)\"; fi; "
            % (ino, off, off + 1, f, READ_MAX, f, ino, off + 1, f, READ_MAX, READ_MAX, f))


def _whole(data):
    """(the whole lines in `data`, the bytes they take); a cut-off last line waits, unless it fills a whole read."""
    end = data.rfind(b"\n") + 1
    if end == 0 and len(data) >= READ_MAX:
        return [], len(data)          # one line longer than a read: skipped, never re-read forever
    return data[:end].split(b"\n")[:-1], end


def parse_read(out, state):
    """(where to start next time, the new lines) from read_sh's output read with `state` (None: a first look)."""
    kv = _ad.kv_lines(out)
    parts = kv.get("st", "").split()
    ino, size = (parts[0], int(parts[1])) if len(parts) == 2 and all(p.isdecimal() for p in parts) else ("none", 0)
    if state is None:
        return (ino, size), []
    lines = []
    if "old.b64" in kv:
        lines += _whole(_raw(kv["old.b64"]))[0]
    if "new.b64" not in kv:
        return (ino, 0 if ino == "none" else state[1]), lines
    got, used = _whole(_raw(kv["new.b64"]))
    start = state[1] if ino == state[0] and size >= state[1] else 0
    return (ino, start + used), lines + got


def _raw(text):
    try:
        return base64.b64decode(text or "", validate=False)
    except ValueError:
        return b""


def penalties(lines):
    """B3's ban, tempban and kick lines (schema 1) among `lines`, as dicts."""
    out = []
    for line in lines:
        try:
            doc = json.loads(line.decode("utf-8", "replace"))
        except ValueError:
            continue
        if isinstance(doc, dict) and doc.get("schema") == 1 and doc.get("event") in KINDS:
            out.append(doc)
    return out


def _clean(value, cap):
    if not isinstance(value, str):
        return ""
    return "".join(c for c in " ".join(value.split()) if unicodedata.category(c)[0] != "C")[:cap]


def _person(part, fallback):
    name = _clean(part.get("name"), _NAME_MAX) if isinstance(part, dict) else ""
    pid = part.get("id") if isinstance(part, dict) else None
    return ("%s (@%d)" % (name or "?", pid)) if isinstance(pid, int) and not isinstance(pid, bool) else (name or fallback)


def alert_text(doc, server_name):
    """(title, body) for one penalty line: the title names no one; the body names the player and the admin."""
    title, body = _WORDS[doc["event"]]
    minutes = doc.get("duration_minutes")
    text = body.format(target=_person(doc.get("target"), "a player"), admin=_person(doc.get("admin"), "B3"),
                       minutes=minutes if isinstance(minutes, int) and not isinstance(minutes, bool) else "?")
    reason = _clean(doc.get("reason"), _REASON_MAX)
    return title.format(server=server_name), text + (": %s" % reason if reason else ".")


def summary_text(docs, server_name):
    """(title, body) for many penalties from one server in one look: counts only."""
    n = {k: sum(1 for d in docs if d["event"] == k) for k in KINDS}
    return ("B3 gave %d penalties on %s" % (len(docs), server_name),
            "%d bans, %d temporary bans and %d kicks since the last look." % (n["ban"], n["tempban"], n["kick"]))


def _alert(gs, docs):
    from panel.services import notifications     # it is imported by the monitor, which imports this
    if not docs or notifications.alerts_muted(gs):
        return
    texts = [summary_text(docs, gs.name)] if len(docs) > FOLD_AT else [alert_text(d, gs.name) for d in docs]
    for title, body in texts:
        notifications.notify(EVENT, title, body, server=gs)


def _look(gs):
    """Read what server `gs`'s B3 added since the last look and alert on its penalties. Never raises."""
    from panel.ops import ssh_manager as _sm
    from panel.routes._shared import game_account_write_refusal
    with _LOCK:
        state = _STATE.get(gs.id)
    try:
        if game_account_write_refusal(gs.remote, gs.short_name, reading=True):
            return
        out, _err, rc = _sm.shell_as_game_user(gs.remote, gs.short_name, read_sh(gs.short_name, state), timeout=20)
    except Exception:  # noqa: BLE001 - an unreachable host is the next look's job
        _log.debug("b3 events: read failed for server %s", gs.id, exc_info=True)
        return
    if rc != 0:
        return                       # no read is no measurement: the next look tries from the same place
    new_state, lines = parse_read(out, state)
    with _LOCK:
        _STATE[gs.id] = new_state
    _alert(gs, penalties(lines))


def watched(by_remote, probes):
    """The servers to look at: B3 alerts on, among the monitor's installed servers by host, on a host found reachable.

    `by_remote` is the monitor sweep's own {host id: [GameServer]} and `probes` its {host id: probe}, so this
    asks the database nothing; taken before the sweep commits, so the servers without alerts are not read
    again after it.
    """
    return [gs for rid, servers in by_remote.items() if (probes.get(rid) or {}).get("reachable") for gs in servers
            if getattr(gs, "b3_alerts", False) and _ad.B3 in _ad.offered(gs.game_type)]


def sweep(servers):
    """One look at each of `servers` (watched()'s). Never raises."""
    for gs in servers:
        _look(gs)
