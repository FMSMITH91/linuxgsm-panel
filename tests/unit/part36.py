"""Part 36 of the unit suite: ws6-security — closed code-scanning alerts and advisories, re-checked.

What the re-check found still open, each driven through the code that calls it:

* V1 (GHSA-hh39-76g3-wxcx, reopened by #374): the account probe put a stored account name RAW
  inside double-quoted echo text, run as root on a sudo-enabled remote. privileged_accounts now
  refuses a name that is not a plain account word before any probe is built; the probe passes
  each name as a quoted printf argument; discover's import checks the name before it asks the
  host. The uninstall of such a row then removes the ROW and touches no host — the way out the
  load-time warning promises — instead of re-running the payload on every click, and says so
  without repeating the stored name.
* F1 (alert #101): when install step 6 raised, the post-start re-open opened every port `details`
  reported — "Query 22" included — because the withheld set was only ever written on step 6's
  success path. The re-open now works out its own filter, opens only the server's own port when
  step 6 never decided, says the firewall step failed (and who can open the ports, since the
  Firewall page takes Manage Remotes), logs it at warning and records it on the audit entry.
* F2 (alerts #97/#102): the install recorded Autostart On whatever the crontab got. Both cron
  writes' answers are kept now, and the column is read back from the crontab. The VPS proof of
  that fix found its corner: a retry whose writes and read-back all failed recorded Off over the
  monitor line an earlier attempt wrote. A failed write now changes nothing (a new row starts Off,
  as an import's does), and the unconfirmed state is logged at warning.
* F3 (alert #10): run_as_game_user returned str() of ANY exception from its argument check into
  the action's message. A non-VerbError now gives fixed text and is logged.
* V8: seven GAMEDIG_TYPE values were not game ids in gamedig 5.3.3 (old ids it resolves only with
  --checkOldIDs, and "minecraftpe", which is none at all). Every value is held to the pinned
  version's id list, tests/unit/gamedig_game_ids.txt. Once Bedrock's id answered, its reply —
  numplayers and an EMPTY player list — read as a confident 0 to every reader that counted the
  list: the hourly restart-when-empty line, a queued restart, the reboot confirm and the dashboard.
  Every reader now counts _core.GAMEDIG_HUMANS_JQ (numplayers less bots, or the list, whichever is
  larger), driven here through each reader's REAL jq filter against a stand-in gamedig, and the
  daily upgrade pass heals the hourly lines already on hosts. The longest such line still fits
  cron's 1000-byte command buffer.
* The maintenance probe's pgrep pattern was built from an unchecked stored name, and the
  _rewrite_crontab and run_as_game_user own guards were held by no check (each was redundant to a
  later refusal, so deleting it failed nothing).

HOW IT RUNS. On part12's Flask app, database and client (imported; part12 has run by then, so
importing it runs nothing again), with part12's transport tripwire re-armed for this part's
duration and every stub undone in its finally. The install steps are driven through
_configure_and_start, the install job's own call, against a scripted host; the account probe runs
in a real bash. The gamedig readers run their own command in bash with real jq, and the hourly
restart line runs under sh in cron's environment, each with a `gamedig` shell function that answers
only the type the panel should send (skipped, as SKIP, where there is no jq). It ends by checking
nothing it drove reached a transport.
"""
import contextlib as _contextlib36
import json as _json36
import logging as _logging36
import os
import shutil as _shutil36
import subprocess as _sp36  # nosec B404 - runs bash on the probe text this part builds
import tempfile as _tf36
from types import SimpleNamespace as NS

import sqlalchemy as _sa36

from unit import REPO_ROOT as _ROOT36
from unit.part01 import check, skip
from unit.part12 import (P9_ADMIN, _P9_TRIPPED, _p9, _p9_app, _p9_audit, _p9_client, _p9_core,
                         _p9_json, _p9_patch, _p9_restore_all, _p9_sm, _p9_so, _p9_trip)
from panel.db.models import GameServer, RemoteServer, db
from panel.ops.ssh_manager import cron as _cron36
from panel.ops.ssh_manager import files as _files36
from panel.ops.ssh_manager import game as _game36
from panel.routes import _shared as _sh36
from panel.routes import discover as _disc36
from panel.routes import manage_servers as _ms36
from panel.security import privileged as _priv36
from panel.services import monitoring as _mon36

_TRIP36_START = len(_P9_TRIPPED)
# Every shape a stored name can break out of shell text with, and the ones that are merely wrong.
_BAD36 = ["gm$(id)", "gm`id`", 'gm";id;"', "gm';id;'", "x; id > /dev/null; #", "a b", "-u root",
          "../x", "", "root", "#0", "gm2\n", None, "a" * 65]
_mine36 = {"hosts": [], "servers": []}
# The names the fixes added, read with a stand-in when a tree does not have them yet, so an unfixed
# tree fails these checks by name instead of crashing the part on an AttributeError.
_INVALID36 = getattr(_sh36, "INVALID_ACCOUNT_NAME", "<no INVALID_ACCOUNT_NAME>")
_FW_FAILED36 = getattr(_ms36, "FIREWALL_STEP_FAILED", "<no FIREWALL_STEP_FAILED>")
_UNCHECKED36 = getattr(_p9_core, "LGSM_ARGS_UNCHECKED", "<no LGSM_ARGS_UNCHECKED>")


class _Records36(_logging36.Handler):
    """Every record a logger emits at WARNING or above, kept."""

    def __init__(self):
        super().__init__(_logging36.WARNING)
        self.records = []

    def emit(self, record):
        self.records.append(record)


@_contextlib36.contextmanager
def _capture36(logger):
    """`logger`'s WARNING records, whatever an earlier part left its level or `disabled` at."""
    rec = _Records36()
    saved = (logger.disabled, logger.level)
    logger.disabled = False
    logger.setLevel(_logging36.WARNING)
    logger.addHandler(rec)
    try:
        yield rec
    finally:
        logger.removeHandler(rec)
        logger.disabled = saved[0]
        logger.setLevel(saved[1])


def _host36(name, host, **kw):
    with _p9.app_context():
        r = RemoteServer(name=name, host=host, port=22, username=kw.pop("username", "admin"),
                         auth_method=kw.pop("auth_method", "key"), auth_credential="",
                         is_online=True, **kw)
        db.session.add(r)
        db.session.commit()
        _mine36["hosts"].append(r.id)
        return r.id


def _server36(rid, short, port, game_type="csgo"):
    with _p9.app_context():
        gs = GameServer(remote_id=rid, name="p36-" + short, short_name=short, game_type=game_type,
                        port=port, installed=True, status="offline")
        db.session.add(gs)
        db.session.commit()
        _mine36["servers"].append(gs.id)
        return gs.id


def _set_short_name36(sid, name):
    """Store `name` as the row's short_name the way a pre-validator database or a hand edit did.

    A Core UPDATE, past the ORM: the model's @validates hook refuses it on assignment, which is
    the point — it never looks again on a load.
    """
    table = GameServer.__table__
    with _p9.app_context():
        db.session.execute(_sa36.update(table).where(table.c.id == sid).values(short_name=name))
        db.session.commit()


def _exists36(sid):
    with _p9.app_context():
        return db.session.get(GameServer, sid) is not None


# ════════════════════════════════════════════════════════════════════════════════════════════════
# V1 — the account probe never carries a raw name
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _probe_in_bash36():
    """The probe, run by a real bash over hostile names: nothing expands, each name comes back."""
    marks = _tf36.mkdtemp(prefix="lgsm-unit-p36-")
    try:
        names = ["x$(touch %s/a)" % marks, "x`touch %s/b`" % marks, 'x";touch %s/c;"' % marks,
                 "x';touch %s/d;'" % marks]
        out = _sp36.run(["bash", "-c", _sh36._account_probe_cmd(names)],  # nosec B603 B607 - bash on this part's own probe text
                        capture_output=True, text=True, timeout=60).stdout
        made = sorted(os.listdir(marks))
    finally:
        _shutil36.rmtree(marks, ignore_errors=True)
    check("V1 account probe (real bash): a name carrying $(...), backticks, \" or ' runs nothing — "
          "the name is a quoted printf argument, never part of the text bash parses",
          made == [], "markers created: %r; output %r" % (made, out[:300]))
    back = [ln[len("NOACCT "):] for ln in out.splitlines() if ln.startswith("NOACCT ")]
    check("V1 account probe (real bash): ...and each name comes back on its line byte for byte",
          back == names, repr((back, names)))


def _probe_sent36(calls):
    """A run_command stand-in that records what it is asked: `calls` gets (cmd, sudo)."""
    def _run(_remote, cmd, timeout=30, sudo=None, stdin_text=None):
        calls.append((cmd, sudo))
        return ("", "SSH command timed out", -1)
    return _run


def _probe_raises36(calls):
    """...and one that raises, as the paramiko transport does."""
    def _run(_remote, cmd, timeout=30, sudo=None, stdin_text=None):
        calls.append((cmd, sudo))
        raise ConnectionError("SSH connection failed")
    return _run


def _privileged_refusals36():
    """privileged_accounts refuses each hostile name by name, on both transports, asking nothing."""
    remote = NS(id=93601, host="192.0.2.60", username="admin", is_local=False, auth_method="key",
                sudo_enabled=True)
    for label, make in (("paramiko (raises)", _probe_raises36),
                        ("tailscale/local (returns rc -1)", _probe_sent36)):
        calls, misses = [], []
        _p9_patch(_p9_core, "run_command", make(calls))
        for name in _BAD36:
            got = _sh36.privileged_accounts(remote, [name])
            if not (isinstance(got, dict) and name in got) or calls:
                misses.append("%r -> %r, sent %r" % (name, got, [c[0][:60] for c in calls]))
                calls.clear()
        check("V1 privileged_accounts over %s: every hostile or invalid name is refused as a "
              "definite answer, and the host is never asked" % label, not misses,
              "; ".join(misses[:3]))
    check("V1 privileged_accounts: a name that is not a plain account word is refused AS that — "
          "not as root, and not as a host that could not be asked",
          _sh36.privileged_accounts(remote, ["gm$(id)"]) == {"gm$(id)": _INVALID36},
          repr(_sh36.privileged_accounts(remote, ["gm$(id)"])))


def _write_refusal36():
    """A file or cron write as such an account is refused, saying why, without asking the host."""
    remote = NS(id=93602, host="192.0.2.61", username="admin", is_local=False, auth_method="key",
                sudo_enabled=True)
    calls = []
    _p9_patch(_p9_core, "run_command", _probe_sent36(calls))
    why = _sh36.game_account_write_refusal(remote, "gm$(id)")
    check("V1 write refusal: a write as an account whose stored name is not a plain word is "
          "refused with that reason — not 'can become root', and the name is not echoed back",
          isinstance(why, str) and "not a plain account name" in why and "become root" not in why
          and "$(id)" not in why and not calls, repr((why, calls)))
    with _sh36._ACCOUNT_VERDICTS_LOCK:
        for key in [k for k in _sh36._ACCOUNT_VERDICTS if k[0] == remote.id]:
            del _sh36._ACCOUNT_VERDICTS[key]


def _uninstall_bad_row36():
    """Remove on a row whose short_name is a payload: the row goes, and nothing reaches the host."""
    rid = _host36("p36-uninstall-host", "192.0.2.62", sudo_enabled=True)
    sid = _server36(rid, "p36bad", 27300)
    _set_short_name36(sid, "gm$(id)")
    sent = []
    _p9_patch(_p9_core, "run_command", _probe_sent36(sent))
    _p9_patch(_p9_core, "run_privileged",
              lambda server, verb, args=(), **k: (sent.append((verb, list(args))), ("", "", 0))[1])
    _p9_patch(_p9.socketio, "emit", lambda *a, **k: None)
    resp = _p9_client(P9_ADMIN).post("/servers/%d/delete" % sid,
                                      headers={"X-Requested-With": "XMLHttpRequest"})
    body = _p9_json(resp)
    msg = body.get("message") or ""
    check("V1 uninstall: a row whose stored short_name is a shell payload is removed from the "
          "panel — the way out the load-time warning promises — and the host is never touched "
          "(no probe, no stop, no userdel)",
          resp.status_code == 200 and body.get("success") is True and not _exists36(sid)
          and not sent and "removed from the panel" in msg, repr((resp.status_code, body, sent[:3])))
    _uninstall_words36(msg, _p9_audit("uninstall_server").detail)


def _uninstall_words36(msg, detail):
    """What that uninstall says, to the operator and in the audit log.

    The refusal to write as such an account does not repeat the name (it is exactly the text the
    panel refuses to handle), and neither may the uninstall's own sentence; nor may either speak of
    an account that was kept, when nothing on the host was asked about at all.
    """
    said = ("gm$(id)" in msg, "NOT deleted" in msg, "nothing on" in msg and "was touched" in msg,
            "nothing on the host was touched" in detail, "account was left" in detail)
    check("V1 uninstall: ...and its message does not repeat the stored name or call it an account "
          "left on the host — it says nothing on the host was touched; the audit entry agrees",
          said == (False, False, True, True, False), repr((said, msg, detail)))


def _discover_selection36():
    """The import from discover asks the host only about names the import itself accepts."""
    remote = NS(id=93603, host="192.0.2.63", username="admin", is_local=False, auth_method="key",
                sudo_enabled=True)
    calls = []

    def _answer(_remote, cmd, timeout=30, sudo=None, stdin_text=None):
        calls.append(cmd)
        return ("ACCT plaingame 1001 plaingame\nLGSM_ACCT_PROBE_DONE\n", "", 0)
    _p9_patch(_p9_core, "run_command", _answer)
    bad = "gm$(id)"
    discovered = {bad: {"csgo"}, "plaingame": {"csgo"}}
    refused = _disc36._privileged_selection(
        remote, [{"user": bad, "game_type": "csgo"}, {"user": "plaingame", "game_type": "csgo"}],
        discovered)
    check("V1 discover import: a /home name the import would refuse never reaches the host's "
          "probe; a plain one beside it is still asked about",
          refused == [] and len(calls) == 1 and bad not in calls[0] and "plaingame" in calls[0],
          repr((refused, calls)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# F1 / F2 — the install's firewall step and Autostart, through _configure_and_start
# ════════════════════════════════════════════════════════════════════════════════════════════════
# A scripted host. Each knob is a list read front to back, the last value repeating; a value that
# is an Exception is raised. `listen_pre` answers port scans before the first start, `listen`
# after it.
_h36 = {}
_ufw36 = []        # every remote_ufw_allow_game_ports call: (phase, sorted ports)
_fin36 = []        # every job.finish: (message, warn)
_MONITOR36 = [{"cmd": "monitor", "desc": "Monitor"}, {"cmd": "start", "desc": "Start"}]


def _h36_reset(**kw):
    _h36.clear()
    _h36.update(detect=[{"game_port": None, "open_ports": []}], listen_pre=[set()],
                listen=[set()], cmds=[_MONITOR36], cron5=[(True, "")], cron7=[(True, "")],
                cron_list=[[{"role": "autostart"}]], started=False, on_start=None)
    _h36.update(kw)
    _ufw36.clear()
    _fin36.clear()


def _h36_next(key):
    seq = _h36[key]
    v = seq.pop(0) if len(seq) > 1 else seq[0]
    if isinstance(v, Exception):
        raise v
    return v


def _run_as36(remote, user, action, **k):
    if action == "start":
        _h36["started"] = True
        if _h36["on_start"]:
            _h36["on_start"]()
    return ("", "", 0)


def _stub_install36():
    """Every host call steps 5 to the end make, answered from the script."""
    _p9_patch(_ms36, "detect_game_ports", lambda r, s, _lg: _h36_next("detect"))
    _p9_patch(_ms36, "_remote_listening_ports",
              lambda r: _h36_next("listen" if _h36["started"] else "listen_pre"))
    _p9_patch(_ms36, "remote_ufw_allow_game_ports",
              lambda r, ports, name: (_ufw36.append(("post" if _h36["started"] else "step6",
                                                     sorted(ports))), (list(ports), ""))[1])
    _p9_patch(_ms36, "remote_ufw_close_game_port", lambda *a, **k: (0, "", []))
    _p9_patch(_ms36, "lgsm_write_config", lambda *a, **k: (True, ""))
    _p9_patch(_ms36, "_resolve_source_aux_ports", lambda *a, **k: {})
    _p9_patch(_ms36, "ensure_persistent_bans", lambda *a, **k: None)
    _p9_patch(_ms36, "install_game_cron", lambda r, s, _lg, supported: _h36_next("cron5"))
    _p9_patch(_ms36, "set_autostart", lambda r, s, on, _lg=None: _h36_next("cron7"))
    _p9_patch(_ms36, "time", NS(time=__import__("time").time, sleep=lambda s: None,
                                monotonic=__import__("time").monotonic))
    _p9_patch(_p9_sm, "list_server_commands", lambda r, s, _lg: _h36_next("cmds"))
    _p9_patch(_p9_sm, "protected_host_ports", lambda r: {22})
    _p9_patch(_p9_sm, "remote_ufw_tagged_ports", lambda r, n: set())
    _p9_patch(_p9_sm, "_invalidate_port_scan", lambda rid: None)
    _p9_patch(_p9_sm, "run_as_game_user", _run_as36)
    _p9_patch(_p9_sm, "list_cron_jobs", lambda r, s, _lg: _h36_next("cron_list"))


def _install36(rid, name, port, **host):
    """Steps 5 to the end of a csgo install of `name` on `port`, as the job runs them. -> row id."""
    with _p9.app_context():
        sid = _ms36._create_install_row(rid, name, name, "csgo", port).id
    _mine36["servers"].append(sid)
    _configure36(rid, sid, name, port, **host)
    return sid


def _configure36(rid, sid, name, port, **host):
    """Steps 5 to the end on row `sid` as it stands: a retry runs the job again on the same row."""
    _h36_reset(**host)
    job = NS(app=_p9, gs_id=sid, remote_id=rid, short_name=name, game_type="csgo",
             lgsm_name="csgoserver", final_port=port, content_games=[], run=None,
             p=lambda *a, **k: None, fail=lambda *a, **k: _fin36.append(("FAILED", a)),
             finish=lambda msg, warn=False: _fin36.append((msg, warn)))
    with _p9.app_context():
        _ms36._configure_and_start(job, db.session.get(RemoteServer, rid),
                                   db.session.get(GameServer, sid))
    return sid


def _opened36(phase):
    return [ports for ph, ports in _ufw36 if ph == phase]


def _f1_step6_raises36(rid):
    """The spec's case: step 6 raises, and `details` then reports Query 22."""
    _install36(rid, "p36fw1", 27400,
               detect=[ConnectionError("details timed out"),
                       {"game_port": 27400, "open_ports": [22, 27400, 27401]}], listen=[{27400}])
    check("F1 install: when step 6 raises and `details` then reports Query 22, no firewall call "
          "opens 22 — the post-start re-open no longer trusts step 6 to have finished",
          not any(22 in ports for _ph, ports in _ufw36), repr(_ufw36))
    check("F1 install: ...and with step 6 undecided, the post-start re-open opens the server's own "
          "port and nothing else `details` reported", _opened36("post") == [[27400]], repr(_ufw36))
    msg, warn = _fin36[-1] if _fin36 else ("", None)
    check("F1 install: ...and the install says the firewall step failed, as a warning, instead "
          "of a clean 'installed and started'",
          warn is True and msg.startswith("p36fw1 installed and started")
          and _FW_FAILED36 in msg, repr(_fin36))
    # The Firewall page takes Manage Remotes; an install takes only Manage Servers (or Install).
    check("F1 install: ...and that sentence does not send a Manage Servers user only to a page "
          "that takes Manage Remotes — it says who else can open the ports",
          "Firewall page" in msg and "or ask someone who manages the host to" in msg, msg)
    audit = _p9_audit("install_complete")
    check("F1 install: ...and the install_complete audit entry records the failed firewall step "
          "— the job's message is gone with the job, the audit log is what stays",
          audit.target == "p36fw1" and "firewall step failed" in audit.detail,
          repr((audit.target, audit.detail, audit.success)))


def _f1_listen_raises36(rid):
    """The verifier's case: the adoption check's port scan raises (paramiko) inside step 6."""
    _install36(rid, "p36fw2", 27410,
               detect=[{"game_port": 27420, "open_ports": [22, 27420, 27421]}],
               listen_pre=[ConnectionError("SSH connection failed")], listen=[{27410}])
    check("F1 install (paramiko): a port scan that raises inside step 6's adoption check leaves "
          "the post-start re-open fail CLOSED — the server's own port, never SSH",
          _opened36("post") == [[27410]] and not any(22 in p for _ph, p in _ufw36), repr(_ufw36))


def _f1_listen_unreadable36(rid):
    """The same host on tailscale/local: the scan RETURNS unreadable, so step 6 decides."""
    _install36(rid, "p36fw3", 27430,
               detect=[{"game_port": 27440, "open_ports": [22, 27440, 27441]}],
               listen_pre=[None], listen=[{27430}])
    check("F1 install (tailscale/local): an unreadable scan is not a raise — step 6 decides, "
          "holds back SSH, and opens the server's own port and the query port",
          _opened36("step6") == [[27430, 27441]], repr(_ufw36))
    check("F1 install (tailscale/local): ...and the post-start re-open opens neither SSH nor the "
          "reported port step 6 could not check, though step 6 reported both",
          _opened36("post") == [[27441]], repr(_ufw36))


def _sibling36(rid):
    """Another server, added on the host from inside the install's start step (its session)."""
    gs = GameServer(remote_id=rid, name="p36-sib", short_name="p36sib", game_type="csgo",
                    port=27460, installed=True, status="offline")
    db.session.add(gs)
    db.session.commit()
    _mine36["servers"].append(gs.id)


def _f1_sibling_after_step6(rid):
    """A server added on the host while this one started: step 6 never saw its block."""
    _install36(rid, "p36fw4", 27450,
               detect=[{"game_port": 27450, "open_ports": [27450]},
                       {"game_port": 27450, "open_ports": [27450, 27460]}],
               listen=[{27450}], on_start=lambda: _sibling36(rid))
    check("F1 install: a port in another server's block is refused by the post-start re-open "
          "itself, though step 6 ran before that server existed",
          _opened36("post") == [[27450]], repr(_ufw36))


def _f1_foreign_listener36(rid):
    """Step 6 raised before it scanned: a port held before the first start is not known to be ours."""
    _install36(rid, "p36fw5", 27470,
               detect=[ConnectionError("details timed out"),
                       {"game_port": 27470, "open_ports": [27470, 27475]}],
               listen=[{27470, 27475}])
    check("F1 install: with step 6 undecided, a reported port that is no other server's and not "
          "SSH is still not opened — whether it was ours before the first start is unknown",
          _opened36("post") == [[27470]], repr(_ufw36))


def _f1_happy36(rid):
    """Control: step 6 works, and a port that appears only at runtime is still opened."""
    _install36(rid, "p36fw6", 27480,
               detect=[{"game_port": 27480, "open_ports": [27480]},
                       {"game_port": 27480, "open_ports": [27480, 27481]}], listen=[{27480}])
    check("F1 install (control): step 6 opens the reported port; the post-start re-open opens a "
          "runtime-only one; the install ends clean",
          _opened36("step6") == [[27480]] and _opened36("post") == [[27480, 27481]]
          and _fin36 == [("p36fw6 installed and started", False)], repr((_ufw36, _fin36)))
    audit = _p9_audit("install_complete")
    check("F1 install (control): ...and its audit entry is a clean success with no firewall note",
          audit.target == "p36fw6" and audit.success is True
          and "firewall" not in audit.detail, repr((audit.target, audit.detail, audit.success)))


def _f1_warning36(rid):
    """Step 6's swallowed exception reaches the log at warning, which production shows."""
    with _capture36(_p9_app._log) as rec:
        _install36(rid, "p36fw7", 27490, detect=[ConnectionError("details timed out")],
                   listen=[{27490}])
    hits = [r for r in rec.records if "firewall step failed" in r.getMessage()]
    check("F1 install: step 6's failure is logged at WARNING with its traceback (it was debug, "
          "which the panel's logging never shows)",
          len(hits) == 1 and hits[0].levelno == _logging36.WARNING and hits[0].exc_info,
          repr([(r.levelname, r.getMessage()[:80]) for r in rec.records]))


def _autostart36(sid):
    with _p9.app_context():
        return db.session.get(GameServer, sid).autostart


def _f2_checks36(rid):
    """What the Autostart column says after the install, per cron outcome."""
    fail = (False, "crontab: could not write")
    cases = [
        # (label, host, expected column)
        ("both cron writes report failure and the crontab reads back empty",
         dict(cron5=[fail], cron7=[fail], cron_list=[[]]), False),
        ("both cron writes report failure and the crontab cannot be read back (tailscale/local)",
         dict(cron5=[fail], cron7=[fail], cron_list=[None]), False),
        ("both cron writes and the read-back raise (paramiko)",
         dict(cron5=[ConnectionError("down")], cron7=[ConnectionError("down")],
              cron_list=[ConnectionError("down")]), False),
        ("both writes report success but the crontab reads back with no monitor line",
         dict(cron_list=[[]]), False),
        ("step 5 wrote the line, step 7's rewrite failed, and the read-back failed",
         dict(cron7=[fail], cron_list=[None]), True),
        ("the command list could not be read (no step-5 write), step 7 wrote the line, and the "
         "read-back failed", dict(cmds=[[]], cron_list=[None]), True),
        ("(control) both writes worked and the crontab has the monitor line", {}, True),
    ]
    for n, (label, host, want) in enumerate(cases):
        sid = _install36(rid, "p36as%d" % n, 27500 + 10 * n, listen=[{27500 + 10 * n}], **host)
        got = _autostart36(sid)
        check("F2 install: Autostart is %s when %s" % ("On" if want else "Off", label),
              got is want, "column %r, finish %r" % (got, _fin36))


def _f2_retry36(rid):
    """The VPS proof's corner: a monitor line already there, and every cron call of this run fails.

    The crontab already holds the line, and this run's two cron writes AND its read-back fail. A
    retry is how an install meets that crontab (a first install goes only into an account it
    creates): the earlier attempt wrote the line, and a failed rewrite installs nothing, so the line
    is still there.
    """
    fail = (False, "crontab: could not write")
    sid = _install36(rid, "p36asr", 27600, listen=[{27600}])   # the earlier attempt: line written
    before = _autostart36(sid)
    with _capture36(_p9_app._log) as rec:
        _configure36(rid, sid, "p36asr", 27600, cron5=[fail], cron7=[fail], cron_list=[None],
                     listen=[{27600}])
    got = _autostart36(sid)
    check("F2 install: a RETRY whose cron writes and read-back all fail keeps the Autostart On the "
          "earlier attempt recorded — its monitor line is still there; step 5 recorded Off over it",
          (before, got) == (True, True), "column before %r, after %r" % (before, got))
    hits = [r for r in rec.records if "Autostart is left On, as last known" in r.getMessage()]
    check("F2 install: ...and that unconfirmed Autostart is logged at WARNING",
          len(hits) == 1 and hits[0].levelno == _logging36.WARNING,
          repr([(r.levelname, r.getMessage()[:90]) for r in rec.records]))
    sid = _install36(rid, "p36asn", 27610, cmds=[[]], cron7=[fail], cron_list=[None],
                     listen=[{27610}])
    check("F2 install: a new server that no write or read reached starts and stays Off (as an "
          "import's row does), not the model's default On", _autostart36(sid) is False,
          repr(_autostart36(sid)))


def _retried36(rid, name, port, **host):
    """(Autostart after an earlier attempt that wrote the line, after a retry run with `host`)."""
    sid = _install36(rid, name, port, listen=[{port}])
    before = _autostart36(sid)
    _configure36(rid, sid, name, port, listen=[{port}], **host)
    return before, _autostart36(sid)


def _f2_retry_paths36(rid):
    """The same corner on the paths a check above does not take: the write raising (paramiko), and
    the command list not read at all, so step 5 never writes (the host unreachable on a retry)."""
    down = ConnectionError("SSH connection failed")
    got = _retried36(rid, "p36asra", 27620, cron5=[down], cron7=[down], cron_list=[down])
    check("F2 install (paramiko): a RETRY whose cron writes and read-back all RAISE keeps the "
          "Autostart On the earlier attempt recorded — a write that raised learned nothing",
          got == (True, True), "column before, after: %r" % (got,))
    got = _retried36(rid, "p36asrb", 27630, cmds=[[]], cron7=[(False, "crontab: could not write")],
                     cron_list=[None])
    check("F2 install (tailscale/local): a RETRY whose command list cannot be read (so step 5 "
          "writes nothing), whose step-7 write fails and whose read-back fails keeps On",
          got == (True, True), "column before, after: %r" % (got,))
    got = _retried36(rid, "p36asrc", 27640, cmds=[down], cron7=[down], cron_list=[down])
    check("F2 install (paramiko): ...and one whose command-list read RAISES keeps On too",
          got == (True, True), "column before, after: %r" % (got,))


def _f2_no_false_warning36(rid):
    """Step 5's write landed: the column is what it got, whatever step 7's write and read do."""
    with _capture36(_p9_app._log) as rec:
        sid = _install36(rid, "p36asw", 27650, cron7=[(False, "crontab: could not write")],
                         cron_list=[None], listen=[{27650}])
    said = [r.getMessage()[:100] for r in rec.records if "unconfirmed" in r.getMessage()]
    check("F2 install: when step 5's write landed, a failed step-7 write and read-back log no "
          "'unconfirmed' warning — step 5's write is what the column says",
          _autostart36(sid) is True and not said, repr((_autostart36(sid), said)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# F3 — no exception text from the argument check reaches an action's message
# ════════════════════════════════════════════════════════════════════════════════════════════════
_SECRET36 = "/root/.ssh/id_ed25519 could not be read"


def _boom36(*a, **k):
    raise RuntimeError(_SECRET36)


def _f3_direct36():
    """run_as_game_user and its helper path: fixed text for a non-VerbError, VerbError as is."""
    srv = NS(id=93604, host="192.0.2.64", username="admin", is_local=False, auth_method="key",
             sudo_enabled=True)
    local = NS(id=93605, host="127.0.0.1", username="local", is_local=True, auth_method="local",
               sudo_enabled=True)
    with _capture36(_p9_core._log) as rec:
        _p9_patch(_priv36, "check_args", _boom36)
        shell = _p9_core.run_as_game_user(srv, "gm2", "details", selfname="gmodserver")
        _p9_restore_one36(_priv36, "check_args")
        _p9_patch(_p9_core, "helper_present", lambda recheck=False: True)
        _p9_patch(_priv36, "helper_argv", _boom36)
        helper = _p9_core.run_as_game_user(local, "gm2", "details", selfname="gmodserver")
        _p9_patch(_priv36, "check_args", lambda verb, args: (_ for _ in ()).throw(
            _priv36.VerbError("not an identifier")))
        verb = _p9_core.run_as_game_user(srv, "gm2", "details", selfname="gmodserver")
    fixed = ("", _UNCHECKED36, 1)
    check("F3 run_as_game_user: an argument check that raises something other than VerbError "
          "answers fixed text, on the shell path and the helper path — never the exception's",
          shell == fixed and helper == fixed, repr((shell, helper)))
    check("F3 run_as_game_user: ...and the exception itself goes to the log, with its traceback",
          sum(1 for r in rec.records if r.exc_info and _SECRET36 in str(r.exc_info[1])) == 2,
          repr([(r.getMessage(), r.exc_info) for r in rec.records][:3]))
    check("F3 run_as_game_user: a VerbError's own text (fixed by design) is still passed on",
          verb == ("", "not an identifier", 1), repr(verb))


def _p9_restore_one36(owner, name):
    """Put one stub back now, rather than at the end of the part."""
    from unit.part12 import _P9_PATCHED
    if (owner, name) in _P9_PATCHED:
        setattr(owner, name, _P9_PATCHED.pop((owner, name)))


def _f3_route36():
    """The caller: the action route's message carries no exception text."""
    rid = _host36("p36-action-host", "192.0.2.65")
    sid = _server36(rid, "p36act", 27600)
    _p9_patch(_priv36, "check_args", _boom36)
    resp = _p9_client(P9_ADMIN).post("/api/server/%d/action" % sid, json={"action": "details"})
    _p9_restore_one36(_priv36, "check_args")
    msg = _p9_json(resp).get("message") or ""
    check("F3 /api/server/<id>/action: a sync action whose argument check raised answers the "
          "panel's own sentence, not the exception's text",
          _SECRET36 not in msg and _UNCHECKED36 in msg,
          repr((resp.status_code, msg[:200])))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# The own guards no check held, and the maintenance probe's pattern
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _own_guards36():
    """run_as_game_user and _rewrite_crontab refuse a bad name THEMSELVES, before anything else."""
    srv = NS(id=93606, host="192.0.2.66", username="admin", is_local=False, auth_method="key",
             sudo_enabled=True)
    asked, shelled = [], []
    _p9_patch(_priv36, "check_args", lambda verb, args: asked.append(list(args)))
    _p9_patch(_p9_core, "shell_as_game_user",
              lambda server, user, sh, **k: (shelled.append(user), ("", "", 0))[1])
    run_miss, cron_miss = [], []
    for name in _BAD36:
        r = _p9_core.run_as_game_user(srv, name, "details", selfname="gmodserver")
        if r != _p9_core.GAME_ACCOUNT_REFUSED or asked:
            run_miss.append("%r -> %r, checked %r" % (name, r, asked[:1]))
            asked.clear()
        c = _p9_core._rewrite_crontab(srv, name, "-vF x", ["* * * * * true"])
        if c != (False, "invalid account name") or shelled:
            cron_miss.append("%r -> %r, ran as %r" % (name, c, shelled[:1]))
            shelled.clear()
    check("own guard run_as_game_user: every bad account name is refused by the function itself "
          "(GAME_ACCOUNT_REFUSED) before the verb table is even asked", not run_miss,
          "; ".join(run_miss[:3]))
    check("own guard _rewrite_crontab: every bad account name is refused by the function itself, "
          "before it takes the crontab lock or runs anything as the account", not cron_miss,
          "; ".join(cron_miss[:3]))


def _maintenance_probe36():
    """The pgrep pattern is built only from names the command builders would accept."""
    sent = []
    _p9_patch(_mon36, "run_command",
              lambda remote, cmd, timeout=30: (sent.append(cmd), ("BUSY\n", "", 0))[1])
    remote = NS(id=93607, host="192.0.2.67")
    bad = [NS(short_name="gm2", lgsm_name="gm|.*server", game_type="gm|.*", name="x"),
           NS(short_name="a b", lgsm_name="csgoserver", game_type="csgo", name="x"),
           NS(short_name="root", lgsm_name="csgoserver", game_type="csgo", name="x")]
    got = [_mon36._lgsm_maintenance_running(remote, gs) for gs in bad]
    check("maintenance probe: a stored name that is not a plain account word is not probed — "
          "`gm|.*` would match every maintenance process on the host and mute this server's "
          "offline alerts for good", got == [False, False, False] and not sent,
          repr((got, sent[:2])))
    sent.clear()
    plain = _mon36._lgsm_maintenance_running(
        remote, NS(short_name="gm2", lgsm_name="csgoserver", game_type="csgo", name="x"))
    check("maintenance probe (control): a plain server is still probed, and BUSY still reads busy",
          plain is True and len(sent) == 1, repr((plain, sent)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# V8 — every gamedig type the panel sends is one the pinned gamedig accepts
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _gamedig_ids36():
    path = os.path.join(_ROOT36, "tests", "unit", "gamedig_game_ids.txt")
    head, ids = {}, set()
    with open(path, encoding="utf-8") as fh:
        for ln in fh.read().splitlines():
            if ln.startswith("# ") and ":" in ln and ln[2:].split(":", 1)[0] in ("version",
                                                                                  "integrity"):
                key, val = ln[2:].split(":", 1)
                head[key] = val.strip()
            elif ln and not ln.startswith("#"):
                ids.add(ln.strip())
    return head, ids


def _gamedig_types36():
    head, ids = _gamedig_ids36()
    with open(os.path.join(_ROOT36, "tools", "gamedig", "package-lock.json"), encoding="utf-8") as fh:
        pinned = _json36.load(fh)["packages"]["node_modules/gamedig"]
    check("V8 gamedig ids: the list is the one for the gamedig the lockfile pins (version and "
          "tarball integrity) — a bump must re-read its games list before this passes",
          head.get("version") == pinned.get("version")
          and head.get("integrity") == pinned.get("integrity") and len(ids) > 300,
          repr((head, pinned.get("version"), pinned.get("integrity"), len(ids))))
    bad = {k: v for k, v in _p9_core.GAMEDIG_TYPE.items() if v not in ids}
    check("V8 GAMEDIG_TYPE: every value is a game id of the pinned gamedig — an old id resolves "
          "only with --checkOldIDs, which the panel never passes, so it answered 'Invalid game' "
          "to every query", not bad, repr(bad))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# V8 (review) — a gamedig reply is counted by its numplayers, not only by its player list
# ════════════════════════════════════════════════════════════════════════════════════════════════
# What gamedig 5.3.3 prints for a Minecraft Bedrock server with 7 of 10 on: its RakNet ping carries
# the counts and no names, so `players` is EMPTY (protocols/minecraftbedrock.js sets numplayers and
# maxplayers only). The other fields are gamedig's Results defaults.
def _bedrock36(numplayers):
    return {"name": "Fake BDS", "map": "Bedrock level",
            "raw": {"edition": "MCPE", "mcVersion": "1.21.40"}, "version": "1.21.40",
            "maxplayers": 10, "numplayers": numplayers, "players": [], "bots": [],
            "queryPort": 19132, "connect": "192.0.2.69:19132", "ping": 2}


_GD_FAILED36 = {"error": "Failed all 1 attempts"}
_GD_HOST36 = "192.0.2.69"


@_contextlib36.contextmanager
def _fake_gamedig36(reply, gdtype="mbe"):
    """(temp dir, shell text defining a `gamedig` function that answers `reply`).

    The function prints `reply` for `--type <gdtype>`, and gamedig's own 'Invalid game' object for
    any other type, so the type the panel sends is part of the test. A function, not a file on
    PATH: it wins over any gamedig the machine has, and inside the restart line's
    `$(PATH=...; gamedig ...)` too.
    """
    root = _tf36.mkdtemp(prefix="lgsm-unit-p36gd-")
    try:
        reply_path = os.path.join(root, "reply.json")
        with open(reply_path, "w", encoding="utf-8") as fh:
            fh.write(_json36.dumps(reply))
        yield root, ('gamedig() { if [ "$1 $2" = "--type %s" ]; then cat "%s"; '
                     'else echo \'{"error":"Invalid game: \'"$2"\'"}\'; fi; }\n'
                     % (gdtype, reply_path))
    finally:
        _shutil36.rmtree(root, ignore_errors=True)


def _sh_with36(fake):
    """A shell_as_game_user stand-in that runs the reader's REAL command, real jq filter included.

    In bash, with `fake` (from _fake_gamedig36) answering for gamedig.
    """
    root, define = fake

    def _run(_server, _user, sh, **_k):
        p = _sp36.run(["bash", "-c", define + sh],  # nosec B603 B607 - bash on the panel's own reader command
                      env={"PATH": "/usr/bin:/bin", "HOME": root},
                      capture_output=True, text=True, timeout=60, check=False)
        return p.stdout, p.stderr, p.returncode
    return _run


def _readers36(reply, game_type="mcb", gdtype="mbe"):
    """{reader: answer} for one gamedig reply, every reader through its real command."""
    srv = NS(id=93608, host=_GD_HOST36, username="admin", is_local=False, auth_method="key")
    with _fake_gamedig36(reply, gdtype) as fake:
        _p9_patch(_p9_core, "shell_as_game_user", _sh_with36(fake))
        _p9_patch(_p9_core, "_gamedig_host", lambda server: _GD_HOST36)
        _p9_patch(_files36, "lgsm_get_values",
                  lambda *a, **k: {"querymode": "2", "querytype": gdtype, "queryport": "19132",
                                   "port": "19132"})
        return {"count": _cron36.player_count(srv, "p36mcb", game_type, 19132),
                "slots": _cron36.player_slots(srv, "p36mcb", game_type, 19132),
                "lgsm": _cron36.player_count_via_lgsm_query(srv, "p36mcb", "bedrockserver"),
                "list": _game36._gamedig_player_list(srv, "p36mcb", game_type, 19132)}


def _count_readers36():
    """player_count, player_slots, player_count_via_lgsm_query and the player list, on real jq."""
    got = _readers36(_bedrock36(7))
    check("V8 count: a Minecraft Bedrock reply (numplayers 7, an empty player list) is 7 to "
          "player_count — never the confident 0 that restart-when-empty and a queued restart act on",
          got["count"] == 7, repr(got))
    check("V8 count: ...and to player_slots (count, max, name), which the dashboard shows and "
          "which skips the LinuxGSM fallback when it answers",
          got["slots"] == (7, 10, "Fake BDS"), repr(got))
    check("V8 count: ...and to player_count_via_lgsm_query (LinuxGSM's own querytype), which the "
          "reboot-when-empty poller reads", got["lgsm"] == 7, repr(got))
    check("V8 count: ...and the player LIST is unknown (None), not the confirmed-empty server [] is "
          "— the Players panel and the chat bot said 'no players connected' with 7 on",
          got["list"] is None, repr(got))
    empty = _readers36(_bedrock36(0))
    check("V8 count (control): a Bedrock reply of 0 is still a counted 0 to every reader, and an "
          "empty list then IS a confirmed-empty server",
          (empty["count"], empty["slots"][0], empty["lgsm"], empty["list"]) == (0, 0, 0, []),
          repr(empty))
    failed = _readers36(_GD_FAILED36)
    check("V8 count (control): a failed query is still unknown to every reader, not 0",
          (failed["count"], failed["slots"], failed["lgsm"], failed["list"])
          == (None, (None, None, None), None, None), repr(failed))
    # numplayers counts bots on a Source server; gamedig reports them as raw.numbots and moves
    # them into `bots` when it can tell them apart. A bot is not a person: a server with only
    # bots on it is empty, as it was when the list alone was counted.
    src = [_readers36({"numplayers": 10, "players": [{"name": "p%d" % i} for i in range(6)],
                       "bots": [{"name": "b%d" % i} for i in range(4)],
                       "raw": {"numbots": 4}}, "gmod", "garrysmod")["count"],
           _readers36({"numplayers": 9, "players": [], "bots": [], "raw": {"numbots": 3}},
                      "gmod", "garrysmod")["count"],
           _readers36({"numplayers": 4, "players": [], "bots": [], "raw": {"numbots": 4}},
                      "gmod", "garrysmod")["count"]]
    check("V8 count: Source bots are not people — 10 with 4 bots is 6, 9 with 3 bots and no "
          "A2S_PLAYER answer is 6, and 4 bots alone is an empty server",
          src == [6, 6, 0], repr(src))


def _queued_action36():
    """The queued restart/stop: run only when the server is online and EMPTY."""
    rid = _host36("p36-queued-host", "192.0.2.70")
    sid = _server36(rid, "p36mcbq", 19132, game_type="mcb")
    ran = []
    _p9_patch(_sh36, "get_server_status", lambda remote, gs, **k: "online")
    _p9_patch(_sh36, "_run_queued_action", lambda app, gs: ran.append(gs.id))
    out = {}
    for n in (7, 0):
        ran.clear()
        with _fake_gamedig36(_bedrock36(n)) as fake:
            _p9_patch(_p9_core, "shell_as_game_user", _sh_with36(fake))
            _p9_patch(_p9_core, "_gamedig_host", lambda server: _GD_HOST36)
            with _p9.app_context():
                gs = db.session.get(GameServer, sid)
                gs.restart_pending = True
                db.session.commit()
                _sh36._settle_queued_action(_p9, gs)
        out[n] = list(ran)
    with _p9.app_context():
        db.session.get(GameServer, sid).restart_pending = False
        db.session.commit()
    check("V8 count: a queued restart on a Bedrock server with 7 on waits — it ran at once while "
          "the empty list counted as nobody; with 0 on it runs (control)",
          out == {7: [], 0: [sid]}, repr(out))


def _reboot_confirm36():
    """/api/remote/<id>/players, which the reboot confirm warns from."""
    rid = _host36("p36-reboot-host", "192.0.2.71")
    sid = _server36(rid, "p36mcbr", 19132, game_type="mcb")
    with _p9.app_context():
        db.session.get(GameServer, sid).status = "online"
        db.session.commit()
    with _fake_gamedig36(_bedrock36(7)) as fake:
        _p9_patch(_p9_core, "shell_as_game_user", _sh_with36(fake))
        _p9_patch(_p9_core, "_gamedig_host", lambda server: _GD_HOST36)
        body = _p9_json(_p9_client(P9_ADMIN).get("/api/remote/%d/players" % rid))
    check("V8 count: the reboot confirm's player read lists the Bedrock server as busy with 7 — "
          "it reported nobody, neither busy nor unknown",
          body.get("total") == 7 and body.get("busy") == [{"name": "p36-p36mcbr", "players": 7}],
          repr(body))


def _restart_line36(game_type="mcb"):
    """[flag line, check line] as set_daily_restart writes them for a Bedrock server today."""
    cap = {}
    _p9_patch(_p9_core, "_rewrite_crontab",
              lambda s, u, grep, add, extra_pre="": (cap.update(add=list(add)), (True, "ok"))[1])
    _p9_patch(_p9_core, "_gamedig_host", lambda server: _GD_HOST36)
    _p9_core.set_daily_restart(None, "p36mcb", "bedrockserver", game_type=game_type, port=19132,
                               enabled=True)
    return cap.get("add") or ["", ""]


def _restart_line_length36():
    """The longest hourly line the panel can write still fits cron's command buffer.

    Debian and Ubuntu's cron reads a crontab command into a fixed MAX_COMMAND (1000) buffer and
    cuts the rest off without a word (entry.c: "we limit it to MAX_COMMAND. XXX - should use
    realloc()"); a cut line is a shell syntax error, and the restart never happens. Counting
    numplayers made the line about a hundred characters longer.
    """
    cap = {}
    _p9_patch(_p9_core, "_rewrite_crontab",
              lambda s, u, grep, add, extra_pre="": (cap.update(add=list(add)), (True, "ok"))[1])
    _p9_patch(_p9_core, "_gamedig_host", lambda server: "255.255.255.255")
    longest = max(_p9_core.GAMEDIG_TYPE, key=lambda g: len(_p9_core.GAMEDIG_TYPE[g]))
    _p9_core.set_daily_restart(None, "u" * 64, "s" * 64, game_type=longest, port=65535,
                               enabled=True)
    lines = cap.get("add") or []
    cmd = lines[1].split(None, 5)[5] if len(lines) == 2 else ""
    check("V8 restart line: the longest one the panel can write (64-character account and script "
          "names, the longest mapped gamedig id, 255.255.255.255:65535) fits Debian cron's "
          "1000-byte command buffer, which cuts a longer line off silently",
          0 < len(cmd) < 1000 and "numplayers" in cmd, "%d characters: %r" % (len(cmd), cmd[:120]))


def _drive_line36(line, reply):
    """Did crontab `line`'s command restart the server, with gamedig answering `reply`?

    Run as cron runs it (sh, cron's own environment). The line removes its flag in the same branch
    that runs the restart, so a flag that is gone is a restart: no stand-in script is needed.
    """
    with _fake_gamedig36(reply) as (root, define):
        home = os.path.join(root, "home")
        os.makedirs(home)
        flag = os.path.join(home, ".restart-pending")
        open(flag, "w", encoding="utf-8").close()
        cmd = line.split(None, 5)[5].replace("/home/p36mcb/", home + "/")
        _sp36.run(["env", "-i", "HOME=" + home, "SHELL=/bin/sh", "PATH=/usr/bin:/bin",  # nosec B603 B607 - cron's own env
                   "sh", "-c", define + cmd], capture_output=True, text=True, timeout=60,
                  check=False)
        return not os.path.exists(flag)


# What main wrote for a Bedrock server (0816ced's shape, with main's "minecraftpe"), and what this
# branch wrote before the review (the gamedig 5 id, still counting the list) — read out of
# daily_restart_check_cmd at refs/remotes/origin/main and at 6d6a45e7.
_RC_MAIN36 = ("10 * * * * [ -f /home/p36mcb/.restart-pending ] && { P=$(PATH=/usr/local/bin:/usr/bin:"
              "/bin; gamedig --type %s " + _GD_HOST36 + ":19132 2>/dev/null | jq -r 'if (.players|"
              "type==\"array\") then (.players|length) else empty end' 2>/dev/null); if [ \"$P\" = 0 ]; "
              "then /home/p36mcb/bedrockserver restart >/dev/null 2>&1; rm -f "
              "/home/p36mcb/.restart-pending; fi; }")


def _upgrade36(listing):
    """(returned, lines written) for one upgrade pass of the p36mcb crontab.

    As app.py's daily pass makes it: with the server's own game type and port.
    """
    cap = {}
    _p9_patch(_p9_core, "run_privileged", lambda server, verb, args=(), **k: (listing, "", 0))
    _p9_patch(_p9_core, "_rewrite_crontab",
              lambda s, u, grep, add, extra_pre="": (cap.update(add=list(add)), (True, "ok"))[1])
    _p9_patch(_p9_core, "_gamedig_host", lambda server: _GD_HOST36)
    ret = _cron36.upgrade_managed_cron_tracking(None, "p36mcb", "bedrockserver", game_type="mcb",
                                                port=19132)
    return ret, cap.get("add")


def _restart_check36():
    """The hourly restart-when-empty line: written, healed in place, and driven under sh."""
    now = _restart_line36()[1]
    check("V8 restart line: a Bedrock server's hourly check asks gamedig 5's id and counts "
          "numplayers", "--type mbe " in now and "numplayers" in now, now)
    seen = (_drive_line36(now, _bedrock36(7)), _drive_line36(now, _bedrock36(0)),
            _drive_line36(now, _GD_FAILED36))
    check("V8 restart line (driven): with 7 on it does NOT restart; with 0 it does; a failed query "
          "does not (it restarted with 7 on while it counted the empty list)",
          seen == (False, True, False), repr(seen))
    healed = {}
    for label, gdtype in (("main's (minecraftpe)", "minecraftpe"), ("the pre-review (mbe)", "mbe")):
        ret, add = _upgrade36(_RC_MAIN36 % gdtype)
        healed[label] = (ret, add == [now], _drive_line36(add[0], _bedrock36(7)) if add else None)
    check("V8 restart line: the daily upgrade pass rewrites main's and the pre-review line to "
          "today's, which does not restart a Bedrock server with 7 on — installed hosts are healed "
          "with no operator action", healed == {k: (True, True, False) for k in healed},
          repr(healed))
    ret, add = _upgrade36("\n".join(_restart_line36()))
    check("V8 restart line: ...and today's line is recognised as the panel's own and left alone "
          "on the next pass", ret is False and add is None
          and any(r.match(now.split(None, 5)[5]) for r in _cron36._restart_check_res(
              "p36mcb", "bedrockserver")), repr((ret, add)))


def _gamedig_counts36():
    if not (_shutil36.which("jq") and _shutil36.which("bash")):
        for name in ("V8 count: every reader counts numplayers", "V8 restart line (driven)"):
            skip(name, "no jq or bash on this machine")
        return
    _count_readers36()
    _queued_action36()
    _reboot_confirm36()
    _restart_check36()


# ════════════════════════════════════════════════════════════════════════════════════════════════
_saved36_emit = _p9.socketio.emit
try:
    # part12's tripwire, again: nothing below may reach a host or run a command on this machine.
    _p9_patch(_p9_core, "get_connection",
              _p9_trip("paramiko", exc=ConnectionError("refused by part36's tripwire")))
    _p9_patch(_p9_core, "_run_via_ssh_cli", _p9_trip("ssh-cli"))
    _p9_patch(_p9_core, "_exec_local_shell", _p9_trip("local-shell"))
    _p9_patch(_p9_core, "_exec_local_argv", _p9_trip("local-argv"))
    _p9_patch(_p9_so, "_run", _p9_trip("system_ops._run"))
    _p9_patch(_p9_so, "_run_verb", _p9_trip("system_ops._run_verb"))
    _p9_patch(_p9.socketio, "emit", lambda *a, **k: None)

    _probe_in_bash36()
    _privileged_refusals36()
    _write_refusal36()
    _uninstall_bad_row36()
    _discover_selection36()

    _stub_install36()
    _H36 = _host36("p36-install-host", "192.0.2.68")
    for _fn36 in (_f1_step6_raises36, _f1_listen_raises36, _f1_listen_unreadable36,
                  _f1_sibling_after_step6, _f1_foreign_listener36, _f1_happy36, _f1_warning36,
                  _f2_checks36, _f2_retry36, _f2_retry_paths36, _f2_no_false_warning36):
        _fn36(_H36)
    _p9_restore_all()

    _p9_patch(_p9_core, "get_connection",
              _p9_trip("paramiko", exc=ConnectionError("refused by part36's tripwire")))
    _p9_patch(_p9_core, "_exec_local_argv", _p9_trip("local-argv"))
    _f3_direct36()
    _p9_restore_all()
    _p9_patch(_p9_core, "get_connection",
              _p9_trip("paramiko", exc=ConnectionError("refused by part36's tripwire")))
    _p9_patch(_p9.socketio, "emit", lambda *a, **k: None)
    _f3_route36()
    _p9_restore_all()
    _own_guards36()
    _p9_restore_all()
    _maintenance_probe36()
    _gamedig_types36()
    _p9_restore_all()
    _p9_patch(_p9_core, "get_connection",
              _p9_trip("paramiko", exc=ConnectionError("refused by part36's tripwire")))
    _p9_patch(_p9_core, "_exec_local_shell", _p9_trip("local-shell"))
    _p9_patch(_p9_core, "_exec_local_argv", _p9_trip("local-argv"))
    _p9_patch(_p9.socketio, "emit", lambda *a, **k: None)
    _gamedig_counts36()
    _restart_line_length36()
finally:
    _p9_restore_all()
    _p9.socketio.emit = _saved36_emit
    with _p9.app_context():
        for _sid36 in _mine36["servers"]:
            _gs36 = db.session.get(GameServer, _sid36)
            if _gs36 is not None:
                db.session.delete(_gs36)
        db.session.commit()
        for _rid36 in _mine36["hosts"]:
            GameServer.query.filter_by(remote_id=_rid36).delete()
            _r36 = db.session.get(RemoteServer, _rid36)
            if _r36 is not None:
                db.session.delete(_r36)
        db.session.commit()

check("part36: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP36_START, repr(_P9_TRIPPED[_TRIP36_START:][:6]))
