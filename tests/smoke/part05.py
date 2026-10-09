"""Part 5 of the smoke suite. Imported for its side effects: see tests/smoke_test.py.

Two markers here are about the split, not the checks. `# pylint: disable=reimported`: each section
imports what it uses under an alias of its own, as it did in the single-file suite, whose one try
hid those imports from Pylint's reimport rule. `# noqa: MC0001` (mccabe): a block whose branches
mccabe counted, until the split, as part of that one try, already reported as too complex.
"""
from smoke.part01 import (_console_window_stub, _sm_core, app, auth, check, client_as, db,
                          DB_PATH, GameServer, Group, join_for, os, RemoteServer, sys, User)
from smoke.part02 import (_ijw_time, _nre, admin2_id, admin_id, encrypt_secret, gs_id, remote_id)
from smoke.part03 import (_AL, _TU, c)
from smoke.part04 import (_dc_src, _dcmod, _InlineWorker, _notif, _re_as, _repo_root, _tg_handler,
                          _tgmod)

# ── The Discord router, which had no coverage at all ──────────────────────────────────────
# The two bots are twins by design and drift is how the /start bug survived: one router grew a
# branch the other didn't. Both are asserted from here on, and the parity gate below is the
# part that catches the next one.
_dc_sent, _dc_acted, _dc_upd, _dc_acks = [], [], [], []
_dc_saved = (_dcmod._dc_reply, _dcmod._dc_server_action, _dcmod._discord_do_update,
             _dcmod._dc_ack)
try:
    _dcmod._dc_ack = lambda tok, chan, text: _dc_acks.append(text)
    _dcmod._dc_reply = lambda tok, chan, text: _dc_sent.append(text)
    _dcmod._dc_server_action = lambda a, tok, chan, action, arg, sender=None: _dc_acted.append(
        (action, arg))
    _dcmod._discord_do_update = lambda a, tok, chan, sender=None: _dc_upd.append("panel")
    _dcmod._handle_discord_command(app, "tok", "1", "!start smoke-cs")
    check("discord: !start <name> runs the start action", _dc_acted == [("start", "smoke-cs")],
          "acted=%s" % _dc_acted)
    _dc_acted.clear(); _dc_sent.clear()
    _dcmod._handle_discord_command(app, "tok", "1", "!update smoke-cs")
    check("discord: !update <name> updates THAT SERVER, not the panel",
          _dc_acted == [("update", "smoke-cs")] and not _dc_upd,
          "acted=%s panel=%s" % (_dc_acted, _dc_upd))
    _dc_acted.clear(); _dc_upd.clear()
    _dcmod._handle_discord_command(app, "tok", "1", "!update")
    check("discord: a bare !update still updates the panel",
          _dc_upd == ["panel"] and not _dc_acted, "acted=%s panel=%s" % (_dc_acted, _dc_upd))
    _dc_sent.clear()
    _dcmod._handle_discord_command(app, "tok", "1", "!help")
    check("discord: !help answers with the command list",
          _dc_sent and "Commands" in _dc_sent[0], "sent=%s" % _dc_sent[:1])
    _dc_sent.clear()
    _dcmod._handle_discord_command(app, "tok", "1", "!nonsense")
    check("discord: an unknown command is refused, not silently dropped",
          _dc_sent and "Unknown command" in _dc_sent[0], "sent=%s" % _dc_sent[:1])
finally:
    (_dcmod._dc_reply, _dcmod._dc_server_action,
     _dcmod._discord_do_update, _dcmod._dc_ack) = _dc_saved

# The same two-message exchange on Discord. The bots are twins by design and drift is how the
# /start bug survived — a behaviour added to one and not the other is the shape that keeps
# recurring, so this is asserted rather than assumed from the shared wording table.
_dfb_acks, _dfb_sent, _dfb_cb = [], [], {}
_dfb_saved = (_dcmod._dc_ack, _dcmod._dc_reply, getattr(app, "_run_action", None))
try:
    _dcmod._dc_ack = lambda tok, chan, text: _dfb_acks.append(text)
    _dcmod._dc_reply = lambda tok, chan, text: _dfb_sent.append(text)

    def _dfb_run_action(gs, remote, action, actor, origin=None, on_done=None):
        _dfb_cb["fn"] = on_done
        return True, "'%s' issued" % action

    app._run_action = _dfb_run_action
    _dcmod._dc_server_action(app, "tok", "1", "restart", "smoke-cs")
    check("discord: a server action acks, then stays quiet until it finishes",
          _dfb_acks and "smoke-cs" in _dfb_acks[0] and _dfb_sent == [],
          "acks=%s sent=%s" % (_dfb_acks, _dfb_sent))
    check("discord: run_action is handed a completion callback",
          callable(_dfb_cb.get("fn")), "cb=%r" % (_dfb_cb.get("fn"),))
    (_dfb_cb.get("fn") or (lambda ok, detail: None))(True, "Server restarted")
    check("discord: the completion message arrives when the action lands",
          len(_dfb_sent) == 1 and "restart finished" in _dfb_sent[0], "sent=%s" % _dfb_sent)
finally:
    _dcmod._dc_ack, _dcmod._dc_reply = _dfb_saved[0], _dfb_saved[1]
    if _dfb_saved[2] is not None:
        app._run_action = _dfb_saved[2]

# Both bots must ack the same commands, and exactly the ones the shared table names. Driven,
# not read off the source: the routers ask commands.working_ack() now, so what matters is what
# each one DOES with the answer. Every text helper is stubbed, so this reaches no host — the
# gate is about which commands announce themselves, not about what they reply.
from panel.services.bots.commands import _WORKING_ACK as _WACK, _ACTION_ACK as _AACK
_ackp_cmds = {"players": "%splayers srv", "console": "%sconsole srv", "say": "%ssay srv hi",
              "status": "%sstatus", "servers": "%sservers", "hosts": "%shosts",
              "connect": "%sconnect srv"}
_ackp_helpers = ("_players_text", "_console_text", "_say_text", "_status_text",
                 "_servers_text", "_hosts_text", "_connect_text")
_ackp_bots = (("telegram", _tgmod, "/", "_tg_ack", "_tg_reply",
               lambda t: _tgmod._tg_dispatch(app, "1:tok", "1", t)),
              ("discord", _dcmod, "!", "_dc_ack", "_dc_reply",
               lambda t: _dcmod._dc_dispatch(app, "tok", "1", t)))
_ackp_seen, _ackp_save = {}, []
_ackp_workers = (_tgmod._TG_WORKER, _dcmod._DC_WORKER)
_tgmod._TG_WORKER = _dcmod._DC_WORKER = _InlineWorker()
try:
    for _bname, _mod, _pfx, _ackn, _replyn, _drive in _ackp_bots:
        for _h in _ackp_helpers + (_ackn, _replyn):
            _ackp_save.append((_mod, _h, getattr(_mod, _h)))
        for _h in _ackp_helpers:
            setattr(_mod, _h, lambda *a, **k: "stubbed")
        setattr(_mod, _replyn, lambda *a, **k: None)
        _seen = set()
        for _cmd, _tmpl in _ackp_cmds.items():
            _hit = []
            setattr(_mod, _ackn, lambda *a, **k: _hit.append(1))
            _drive(_tmpl % _pfx)
            if _hit:
                _seen.add(_cmd)
        _ackp_seen[_bname] = _seen
finally:
    for _mod, _h, _fn in _ackp_save:
        setattr(_mod, _h, _fn)
    _tgmod._TG_WORKER, _dcmod._DC_WORKER = _ackp_workers
check("bots: both routers ack the same set of slow commands",
      _ackp_seen.get("telegram") == _ackp_seen.get("discord") == set(_WACK),
      "telegram=%s discord=%s table=%s" % (sorted(_ackp_seen.get("telegram") or []),
                                           sorted(_ackp_seen.get("discord") or []),
                                           sorted(_WACK)))
# Every action the bots can dispatch needs ack wording, or it falls back to "working on it…"
# and the user is told nothing about what is happening.
_bot_actions = {"start", "stop", "restart", "backup", "update"}
check("bots: every dispatchable action has its own ack wording",
      _bot_actions <= set(_AACK), "missing: %s" % sorted(_bot_actions - set(_AACK)))

# Both routers must handle the same verbs. Neither is the source of truth, so compare the
# quoted command words in each router body — a branch added to one and not the other is
# exactly the shape of the /start and /update bugs.
_dc_handler = _dc_src[_dc_src.index("def _handle_discord_command"):]
_dc_handler = _dc_handler[:_dc_handler.index("\ndef ", 10)]
_verbs = set(_nre.findall(r'"([a-z][a-z-]{1,15})"', _tg_handler))
_dc_verbs = set(_nre.findall(r'"([a-z][a-z-]{1,15})"', _dc_handler))
_only_tg = sorted(_verbs - _dc_verbs - {"help"})      # a bare /start is Telegram-only, by design
_only_dc = sorted(_dc_verbs - _verbs)
check("bots: the Telegram and Discord routers handle the same commands",
      not _only_tg and not _only_dc,
      "telegram-only: %s  discord-only: %s" % (_only_tg, _only_dc))

# ── Revoking Discord's "Accept commands" has to bite at the next MESSAGE ──────────────────
# _on_message froze the channel id and the permission into its default args at IDENTIFY time,
# and a Discord Gateway session is deliberately long-lived — heartbeat every ~41s, reconnect
# only on op 7/9 or a dropped socket. So unticking the box re-rendered the settings page and
# changed nothing else: the next `!stop codserver` in that channel still stopped the server,
# with an audit row attributed to discord:<username>, for minutes or for days, and the panel
# could put no bound on the window. Moving the bot to a new, locked-down channel had the
# mirror-image bug — the OLD channel kept control and the new one was ignored. The Telegram
# twin has always re-read its gate on every poll.
_dcg_cfg = {"discord": {"enabled": True, "accept_commands": True,
                        "bot_token": "enc", "channel_id": "999"}}
_dcg_ran = []


class _DcgStop(Exception):
    """Raised from the watch loop's own backoff sleep, which sits OUTSIDE its try/except — the
    one clean way out of a `while True:` that swallows every other exception."""


class _DcgClock(object):
    def sleep(self, _secs):
        raise _DcgStop()


def _dcg_gateway(_tok, on_message, **_k):
    """Stands in for discord_gateway_run: the session is now live and the handler is fixed for
    the whole of its lifetime, which is the window the bug lived in."""
    on_message("999", False, "!status")                 # still authorised
    _dcg_cfg["discord"]["accept_commands"] = False       # the superadmin unticks the box
    on_message("999", False, "!stop codserver")          # must not reach the dispatcher
    _dcg_cfg["discord"]["accept_commands"] = True
    _dcg_cfg["discord"]["channel_id"] = "1000"           # ...or moves the bot elsewhere
    on_message("999", False, "!stop codserver")          # the old channel loses control
    on_message("1000", False, "!hosts")                  # and the new one gains it


_dcg_saved = (_notif._cfg, _notif.discord_gateway_run, _dcmod._dc_dispatch,
              _dcmod.decrypt_secret, _dcmod.time)
try:
    _notif._cfg = lambda: _dcg_cfg
    _notif.discord_gateway_run = _dcg_gateway
    _dcmod._dc_dispatch = lambda a, tok, chan, text, sender=None: _dcg_ran.append((chan, text))
    _dcmod.decrypt_secret = lambda s: "A" * 50
    _dcmod.time = _DcgClock()
    try:
        _dcmod._discord_command_watch(app)
    except _DcgStop:
        pass                      # one pass through the loop is the whole test
finally:
    (_notif._cfg, _notif.discord_gateway_run, _dcmod._dc_dispatch,
     _dcmod.decrypt_secret, _dcmod.time) = _dcg_saved
check("discord: a command in the authorised channel is honoured (positive control)",
      ("999", "!status") in _dcg_ran, "dispatched=%s" % (_dcg_ran,))
check("discord: unticking 'Accept commands' takes effect at the next message, not the next "
      "socket drop",
      not any(_t.startswith("!stop") for _c, _t in _dcg_ran), "dispatched=%s" % (_dcg_ran,))
check("discord: ...and moving the bot to another channel takes control off the old one",
      ("1000", "!hosts") in _dcg_ran
      and not any(_c == "999" and _t.startswith("!stop") for _c, _t in _dcg_ran),
      "dispatched=%s" % (_dcg_ran,))

# ── /status must not print a player total it never managed to read ───────────────────────
# The total was built with `isinstance(count, int)` as its only handling of the unknown case,
# so a server the panel could not ask contributed nothing and the remainder was then stated as
# a fact. Right after a restart _player_counts is empty because the poller has not completed a
# pass, and six servers with forty people on them answered "Players online: 0". /servers, six
# lines away in the same file, prints "?" for exactly this state.
from panel.services.bots import commands as _btc
_bps = sys.modules["panel.core.panel_state"]._player_counts
_bps_saved = dict(_bps)
with app.app_context():
    _bst_ids = [_g.id for _g in GameServer.query.filter_by(installed=True).all()]
check("bots: /status has installed servers to report on (the checks below need them)",
      len(_bst_ids) >= 1, "%d installed — the /status checks would prove nothing" % len(_bst_ids))
try:
    _bps.clear()                       # nothing polled yet: the window after a restart
    _bst_none = _btc._status_text(app)
    check("bots: /status says the player total could not be read, instead of printing 0",
          "Players online: 0" not in _bst_none and "couldn't be queried" in _bst_none,
          _bst_none)
    _bps.clear()
    for _i in _bst_ids:
        _bps[_i] = {"count": 3, "max": 16}
    _bst_all = _btc._status_text(app)
    check("bots: ...and a total it DID read is still printed plainly (positive control)",
          "couldn't be queried" not in _bst_all
          and ("Players online: %d" % (3 * len(_bst_ids))) in _bst_all, _bst_all)
    # An offline server is a REAL zero (monitoring writes count=0 for it without querying), so
    # this must not start reporting every stopped server as unreadable.
    _bps.clear()
    for _i in _bst_ids:
        _bps[_i] = {"count": 0, "max": 16}
    _bst_zero = _btc._status_text(app)
    check("bots: ...and a confirmed zero is still a zero, not an unknown",
          "couldn't be queried" not in _bst_zero and "Players online: 0" in _bst_zero,
          _bst_zero)
finally:
    _bps.clear()
    _bps.update(_bps_saved)

# ── A list reply has to be capped where it is BUILT, not sliced by the transport ──────────
# _BOT_BODY_MAX exists with a comment saying it belongs in every variable-length builder, and
# was applied in one of the four. On Discord the end of an uncapped body is discord_bot_send's
# bare text[:1900] — a hard slice, no ellipsis, mid-word, mid-row — so a panel with ~45 servers
# answered !servers with a list that stopped part-way through a name and was missing roughly
# the last ten, with nothing saying so.
_cap_rows = ["row %03d %s" % (_i, "x" * 60) for _i in range(200)]
_cap_body = _btc._join_capped(_cap_rows)
_cap_lines = _cap_body.splitlines()
check("bots: a long list reply fits one Discord message and says how many rows it dropped",
      len(_cap_body) < 1900 and _cap_lines[0].startswith("row 000")
      and _cap_lines[-1] == "… and %d more" % (200 - (len(_cap_lines) - 1)),
      "%d chars, %d lines, last=%r" % (len(_cap_body), len(_cap_lines), _cap_lines[-1:]))
check("bots: ...and a list that already fits is left exactly as it was (positive control)",
      _btc._join_capped(["a", "b", "c"]) == "a\nb\nc",
      repr(_btc._join_capped(["a", "b", "c"])))
import inspect as _bot_inspect
for _capfn in ("_players_text", "_servers_text", "_hosts_text"):
    check("bots: %s caps its body before the transport can slice it" % _capfn,
          "_join_capped" in _bot_inspect.getsource(getattr(_btc, _capfn)),
          "uncapped — discord_bot_send will cut this at 1900 characters, mid-row")

# ── A power action the panel already knows is a no-op must say so, not report success ────
# /servers listed a server as online and the very next /start answered
# "✅ 'start' issued — status updates in a few seconds". _run_action never consulted the status
# it had just rendered, and start/stop run in the background with their output discarded, so
# LinuxGSM's own "Server already started" never reached anyone either. Both halves matter, so
# both are asserted: the refusal AND the cases that must still go through — a stale "online"
# (the server actually died), a hung server the column calls offline, an unreadable host, and
# 'restart', which is deliberately never guarded because it is the way out of a wrong refusal.
import time as _pt
# Each stub goes where its NAME resolves, which the split made different per name:
# run_as_game_user and set_game_priority moved to panel/routes/server_detail with _run_action,
# while server_live_metrics is still read by _live_run_state in app.py. Stubbing the wrong
# module does not error — the assignment succeeds and simply intercepts nothing, turning these
# power checks into proof that a stub was never called. unit_test's stub-target gate names it.
_pa_saved = (_sm_core.server_live_metrics, _sm_core.run_as_game_user, _sm_core.set_game_priority)
_pa_ran, _pa_prio = [], []


def _pa_rag(remote, short, cmd, *a, **k):
    _pa_ran.append(cmd)
    return ("", "", 0)


def _pa_metrics(up, readable=True):
    """The live-metrics shape _live_run_state reads. ram_total==0 is its 'SSH blip' sentinel."""
    return lambda *a, **k: {"ram_total": (8 << 30) if readable else 0,
                            "port_open": up, "game_procs": 1 if up else 0}


def _pa_status(st):
    with app.app_context():
        db.session.get(GameServer, gs_id).status = st
        db.session.commit()


def _pa_wait(bucket, secs=5.0):
    """Block until the background power-action thread records its call — so the stubs are never
    restored out from under it (a real run_as_game_user here would SSH to 127.0.0.1)."""
    _dl = _pt.time() + secs
    while _pt.time() < _dl and not bucket:
        _pt.sleep(0.02)
    return bool(bucket)


def _pa_post(action):
    _pa_ran.clear(); _pa_prio.clear()
    return c.post("/api/server/%d/action" % gs_id, json={"action": action}).get_json() or {}


try:
    _sm_core.run_as_game_user = _pa_rag
    # set_game_priority resolves in panel/routes/server_detail now, not app — a stub on app
    # would be installed on a name nothing reads.
    _sm_core.set_game_priority = lambda *a, **k: _pa_prio.append(1)

    # Online in the column AND confirmed running on the host: refuse, and don't touch the host.
    _pa_status("online"); _sm_core.server_live_metrics = _pa_metrics(True)
    _j = _pa_post("start")
    check("power: start on a running server is refused, not reported as issued",
          _j.get("success") is False and "already running" in (_j.get("message") or ""),
          "got %s" % _j)
    check("power: the refused start never reached the host", not _pa_ran, "ran %s" % _pa_ran)
    # The same lie in the other direction.
    _pa_status("offline"); _sm_core.server_live_metrics = _pa_metrics(False)
    _j = _pa_post("stop")
    check("power: stop on a stopped server is refused, not reported as issued",
          _j.get("success") is False and "already stopped" in (_j.get("message") or ""),
          "got %s" % _j)
    check("power: the refused stop never reached the host", not _pa_ran, "ran %s" % _pa_ran)

    # A STALE "online" — the column says up, the host says down — must not block the recovery.
    _pa_status("online"); _sm_core.server_live_metrics = _pa_metrics(False)
    _j = _pa_post("start")
    check("power: a stale 'online' does not block starting a server that has died",
          _j.get("success") is True and "issued" in (_j.get("message") or ""), "got %s" % _j)
    check("power: that start really ran on the host", _pa_wait(_pa_ran) and _pa_wait(_pa_prio),
          "ran %s" % _pa_ran)
    # A hung server: nothing listening, but processes alive. The column calls that offline —
    # refusing the stop would leave the one command that fixes it unreachable.
    _pa_status("offline")
    _sm_core.server_live_metrics = lambda *a, **k: {"ram_total": 8 << 30, "port_open": False,
                                                   "game_procs": 3}
    _j = _pa_post("stop")
    check("power: a hung server (offline column, live processes) can still be stopped",
          _j.get("success") is True and _pa_wait(_pa_ran), "got %s ran %s" % (_j, _pa_ran))
    # An unreadable host proves nothing, so it can never be grounds for a refusal. Checked on
    # the stop side: start is trivially safe (a falsy read lets it through either way), while
    # losing the "couldn't read" sentinel would turn an SSH blip into "already stopped".
    _pa_status("offline"); _sm_core.server_live_metrics = _pa_metrics(False, readable=False)
    _j = _pa_post("stop")
    check("power: an unreadable host fails open — the stop is not refused",
          _j.get("success") is True and _pa_wait(_pa_ran), "got %s" % _j)
    # restart is the escape hatch; it is correct from either state and must never be guarded.
    _pa_status("online"); _sm_core.server_live_metrics = _pa_metrics(True)
    _j = _pa_post("restart")
    check("power: restart is never refused, whatever the status says",
          _j.get("success") is True and _pa_wait(_pa_ran) and _pa_wait(_pa_prio), "got %s" % _j)

    # ── The panel half of the chat bots' "I'll tell you when it's done" ──────────────────
    # run_action returns as soon as the work is handed to a thread, so (True, "issued") means
    # ACCEPTED, not finished. The web UI has a status column to watch; a chat bot has nothing,
    # so it was left announcing a restart and never able to say how it went. on_done closes
    # that — and it has to fire on BOTH outcomes, because a callback that only reports success
    # leaves a failure indistinguishable from a bot that died.
    _pa_status("offline"); _sm_core.server_live_metrics = _pa_metrics(False)
    _done_ok = []
    with app.app_context():
        _pa_gs = db.session.get(GameServer, gs_id)
        app._run_action(_pa_gs, _pa_gs.remote, "start", None,
                        on_done=lambda ok, detail: _done_ok.append((ok, detail)))
    check("run_action: a backgrounded power action reports back when it finishes",
          _pa_wait(_done_ok) and _done_ok[0][0] is True, "done=%s" % (_done_ok,))
    _done_fail = []
    _sm_core.run_as_game_user = lambda *a, **k: (
        "[ LinuxGSM ] banner\nStarting…\nFailed to start\n", "", 1)
    _pa_status("offline"); _sm_core.server_live_metrics = _pa_metrics(False)
    with app.app_context():
        _pa_gs = db.session.get(GameServer, gs_id)
        app._run_action(_pa_gs, _pa_gs.remote, "start", None,
                        on_done=lambda ok, detail: _done_fail.append((ok, detail)))
    check("run_action: a FAILED backgrounded action reports the failure, not silence",
          _pa_wait(_done_fail) and _done_fail[0][0] is False, "done=%s" % (_done_fail,))
    # LinuxGSM prints its logo first and its verdict last, so the LAST non-empty line is the
    # one worth putting in a chat message — reporting the head would report the banner.
    check("run_action: the completion detail is LinuxGSM's verdict, not its banner",
          _done_fail and _done_fail[0][1] == "Failed to start", "done=%s" % (_done_fail,))
    _sm_core.run_as_game_user = _pa_rag
    # The OTHER background branch. backup/update go through _bg_action, not _bg_power_action,
    # and those are the slow ones — a /backup was the longest silence of the lot.
    _done_long = []
    with app.app_context():
        _pa_gs = db.session.get(GameServer, gs_id)
        app._run_action(_pa_gs, _pa_gs.remote, "backup", None,
                        on_done=lambda ok, detail: _done_long.append((ok, detail)))
    check("run_action: a long action (backup) reports back too, not just power actions",
          _pa_wait(_done_long) and _done_long[0][0] is True, "done=%s" % (_done_long,))
    # The promise only holds because every action a bot can send is backgrounded. If one ever
    # became synchronous, the bot would ack it and then wait for a callback that never comes.
    from app import LONG_ACTIONS as _LONG
    _bg_verbs = {"start", "stop", "restart"} | set(_LONG)
    check("run_action: every action a chat bot can send is a backgrounded one",
          {"start", "stop", "restart", "backup", "update"} <= _bg_verbs,
          "not backgrounded: %s" % sorted({"start", "stop", "restart", "backup", "update"}
                                          - _bg_verbs))
finally:
    (_sm_core.server_live_metrics, _sm_core.run_as_game_user,
     _sm_core.set_game_priority) = _pa_saved
    _pa_status("offline")

# ── A long action's output reaches the console the panel told you to watch ───────────────
# Accepting an update answers "'update' started — watch the live console for progress." That
# was not true of any of the six LONG_ACTIONS. The command ran on its own SSH channel and its
# output went into a Python variable, surfacing only in the audit log afterwards, truncated to
# 300 characters; the console the message points at is a tail of the GAME's console log, which
# an update never writes to. So an operator watching it saw NOTHING for the whole download —
# reported as "it says to watch the console for updates, there is nothing that gets sent".
#
# Four things have to hold, and each is a different way it silently went back to being empty:
# the command must redirect through a file, the file must be registered while it runs, the
# drain must send only what is new, and the POLLER must actually call the drain.
from panel.core.panel_state import _action_output as _ao
from panel.routes._shared import (_action_log_path, _begin_action_tail, _drain_action_output,
                                  _end_action_tail)
from panel.routes import server_files as _r_sf
import re as _lat_re
_ao.clear()
_lat_saved = (_sm_core.run_as_game_user, _sm_core.run_command)
_lat_cmds, _lat_seen, _lat_kw = [], [], []


def _lat_emit(event, payload=None, **kw):
    _lat_seen.append((event, payload, kw.get("room")))


_lat_sio_saved = app.socketio.emit
try:
    app.socketio.emit = _lat_emit

    # 1. The command LinuxGSM is asked to run, and what was registered while it ran.
    _lat_during = []

    def _lat_rag(remote, short, cmd, *a, **k):
        _lat_cmds.append(cmd)
        _lat_kw.append(dict(k))
        _lat_during.append(dict(_ao.get(gs_id) or {}))
        return ("Local build: 1\nRemote build: 2\nUpdate complete\n", "", 0)

    _sm_core.run_as_game_user = _lat_rag
    _sm_core.run_command = lambda *a, **k: ("0", "", 0)   # nothing to tail; drains are no-ops
    with app.app_context():
        _lat_gs = db.session.get(GameServer, gs_id)
        _lat_user = _lat_gs.short_name
        app._run_action(_lat_gs, _lat_gs.remote, "update", None)
    check("long action: it really ran", _pa_wait(_lat_cmds), "cmds=%s" % _lat_cmds)
    _lat_logf = _action_log_path(_lat_user, "update")
    # The route used to hand run_as_game_user a whole shell line — the action, a redirect into
    # this file, a `cat` and an `exit $rc` — which is exactly why that call could not route
    # through a privileged verb. It passes the ACTION plus tee_log now, and run_as_game_user
    # renders the redirect (remote) or the helper writes the file itself (local). Both derive
    # the path from the same two values _action_log_path does; part05 holds that check and the
    # rendering ones, so what this asserts is that the ROUTE still asks for the tee'd log.
    check("long action: it asks for output tee'd through a file the console can tail",
          _lat_kw and _lat_kw[0].get("tee_log") is True,
          "kwargs %r" % (_lat_kw[0] if _lat_kw else None))
    check("long action: ...and passes a bare LinuxGSM action, not a shell fragment",
          _lat_cmds and _lat_cmds[0] == "update",
          "ran %r" % (_lat_cmds[0] if _lat_cmds else None))
    # ...and the whole output must still come BACK to this thread: the audit log entry and the
    # chat bots' completion message are both built from it, so a tee that swallowed it would
    # trade one silence for another. The stub above returns output, and the completion marker
    # checked below is built from it.
    check("long action: fastdl is the one that also needs its prompts answered",
          _lat_kw and "answers" in _lat_kw[0],
          "kwargs %r" % (_lat_kw[0] if _lat_kw else None))
    check("long action: the output file is registered for tailing WHILE it runs",
          _lat_during and _lat_during[0].get("path") == _lat_logf
          and _lat_during[0].get("action") == "update"
          and _lat_during[0].get("user") == _lat_user,
          "registered %s" % (_lat_during,))
    _lat_dl = _pt.time() + 3.0
    while _pt.time() < _lat_dl and gs_id in _ao:
        _pt.sleep(0.02)
    check("long action: ...and deregistered once it's over, so the poller stops asking",
          gs_id not in _ao, "still registered: %s" % (_ao.get(gs_id),))
    _lat_markers = [p.get("data") for (e, p, r) in _lat_seen if e == "console_output"]
    check("long action: the console is told it started and how it ended",
          any("update started" in (m or "") for m in _lat_markers)
          and any("update finished successfully" in (m or "") for m in _lat_markers),
          "markers=%s" % _lat_markers)
    # Same vacuity guard: with no console_output captured, all(...) over the empty filter is
    # True and the room assertion tests nothing.
    _lat_rooms = [r for (e, p, r) in _lat_seen if e == "console_output"]
    check("long action: console_output was actually captured, so the room check sees some",
          len(_lat_rooms) >= 1, "no console_output events — the next check would be vacuous")
    check("long action: the markers go to THIS server's console room only",
          _lat_rooms and all(r == "console_%d" % gs_id for r in _lat_rooms),
          "rooms=%s" % _lat_rooms)

    # 2. The drain itself: new bytes only. A tail that re-sent its window every tick would
    # fill the console with the same SteamCMD spool over and over.
    _lat_seen.clear()
    _lat_file = {"text": ""}

    def _lat_rc(server, command, timeout=30, sudo=None):
        if "stat -c%s" in command and ".panel-" in command:
            t = _lat_file["text"]
            # What the real one-round-trip script prints: the size, then the new bytes.
            _m = _lat_re.search(r"tail -c \+(\d+)", command)
            _pos = (int(_m.group(1)) - 1) if _m else 0
            body = t[_pos:] if len(t) > _pos else ""
            return ("%d\n%s" % (len(t), body)).strip(), "", 0
        return ("0", "", 0)

    _sm_core.run_command = _lat_rc
    with app.app_context():
        _lat_remote = db.session.get(GameServer, gs_id).remote
        _begin_action_tail(app, gs_id, "update", _lat_logf, _lat_user)
        _lat_seen.clear()
        _lat_file["text"] = "Update required\nDownloading 12%\n"
        _drain_action_output(app, _lat_remote, gs_id)
        _lat_first = [p.get("data") for (e, p, r) in _lat_seen if e == "console_output"]
        _lat_seen.clear()
        _drain_action_output(app, _lat_remote, gs_id)          # nothing new since
        _lat_repeat = [p.get("data") for (e, p, r) in _lat_seen if e == "console_output"]
        _lat_file["text"] += "Downloading 97%\nSuccess\n"
        _lat_seen.clear()
        _drain_action_output(app, _lat_remote, gs_id)
        _lat_second = [p.get("data") for (e, p, r) in _lat_seen if e == "console_output"]
        # The file is TRUNCATED under the tail. Running the same action again re-opens its log
        # with `>`, and _begin_action_tail resets the offset — but only after the SSH call is
        # issued, so a tick landing between the two leaves the poller holding an offset past
        # the end of a brand-new file. The drain noticed that already; what it then did was
        # advance the offset to the NEW file's size without ever sending those bytes, so the
        # first chunk of the re-run's output was dropped on the floor and nothing said so.
        _lat_file["text"] = "Second run: validating\n"
        _lat_seen.clear()
        _drain_action_output(app, _lat_remote, gs_id)     # sees size < pos
        _lat_trunc_now = [p.get("data") for (e, p, r) in _lat_seen if e == "console_output"]
        _lat_trunc_pos = dict(_ao.get(gs_id) or {}).get("pos")
        _lat_seen.clear()
        _drain_action_output(app, _lat_remote, gs_id)     # ...and re-reads from the start
        _lat_trunc_next = [p.get("data") for (e, p, r) in _lat_seen if e == "console_output"]
        _end_action_tail(app, gs_id, _lat_remote, "update", 0)
    check("console tail: the first drain sends what the action has written so far",
          _lat_first and "Downloading 12%" in _lat_first[0], "sent %s" % _lat_first)
    check("console tail: a drain with nothing new sends nothing (no repeated window)",
          not _lat_repeat, "re-sent %s" % _lat_repeat)
    check("console tail: the next drain sends ONLY the new lines",
          _lat_second and "Downloading 97%" in _lat_second[0]
          and "Downloading 12%" not in _lat_second[0], "sent %s" % _lat_second)
    check("console tail: a truncated log rewinds the offset instead of skipping past it",
          _lat_trunc_pos == 0, "offset left at %r after the truncation" % (_lat_trunc_pos,))
    check("console tail: ...so the re-run's output is still delivered, one tick later",
          any("Second run: validating" in (m or "")
              for m in (_lat_trunc_now + _lat_trunc_next)),
          "now=%s next=%s" % (_lat_trunc_now, _lat_trunc_next))

    # 2b. TWO long actions on one server, which nothing serialises: every maintenance button
    # posts /api/server/<id>/action, the route hands a LONG_ACTION to a thread and answers
    # within a second, and the button re-enables itself. _action_output is keyed by server_id
    # alone, so the second registration overwrites the first — and _end_action_tail popped
    # whatever was registered rather than its OWN entry. The shorter action finishing therefore
    # deregistered the one still running: every later poller tick returned immediately, so the
    # ten-minute SteamCMD download the panel had just told the operator to watch streamed
    # nothing at all, and the update's own final drain then found no entry either, losing the
    # last and most interesting lines as well.
    with app.app_context():
        _begin_action_tail(app, gs_id, "validate", _lat_logf, _lat_user)
        _begin_action_tail(app, gs_id, "update", _lat_logf, _lat_user)   # overwrites it
        _end_action_tail(app, gs_id, _lat_remote, "validate", 0)         # the OTHER one ends
        _lat_after_other = dict(_ao.get(gs_id) or {})
        _end_action_tail(app, gs_id, _lat_remote, "update", 0)           # ...then its owner
        _lat_after_own = dict(_ao.get(gs_id) or {})
    check("console tail: an action that ends does not deregister a DIFFERENT one still running",
          _lat_after_other.get("action") == "update",
          "left %r registered — the running update's output stops reaching the console the "
          "panel told the operator to watch" % (_lat_after_other or None,))
    # 2c. ...and two runs of the SAME action, each on its own worker, as _bg_action runs them.
    # Ownership was decided by the action NAME, so the first validate to finish popped the
    # registration of the second, still running. Each worker now ends only its own entry.
    import threading as _lat_thr
    _lat_go1, _lat_go2, _lat_b1, _lat_b2 = (_lat_thr.Event() for _ in range(4))

    def _lat_worker(began, go):
        with app.app_context():
            _begin_action_tail(app, gs_id, "validate", _lat_logf, _lat_user)
            began.set()
            go.wait(10)
            _end_action_tail(app, gs_id, _lat_remote, "validate", 0)
    _lat_t1 = _lat_thr.Thread(target=_lat_worker, args=(_lat_b1, _lat_go1))
    _lat_t1.start()
    _lat_b1.wait(10)
    _lat_t2 = _lat_thr.Thread(target=_lat_worker, args=(_lat_b2, _lat_go2))
    _lat_t2.start()
    _lat_b2.wait(10)
    _lat_second = _ao.get(gs_id)
    _lat_go1.set()
    join_for(_lat_t1, 10)                              # the FIRST run finishes
    _lat_still = _ao.get(gs_id)
    _lat_go2.set()
    join_for(_lat_t2, 10)
    check("console tail: a run that ends does not deregister a later run of the SAME action",
          _lat_second is not None and _lat_still is _lat_second,
          "after the first validate ended, %r was registered (the second run's entry was %r)"
          % (_lat_still, _lat_second))
    check("console tail: ...and that later run still deregisters itself when it ends",
          gs_id not in _ao, "left %r registered" % (_ao.get(gs_id),))
    # The other order, the finding's: the LATER run is refused fast and finishes first. It
    # had displaced the earlier run's registration, so popping it left the earlier validate —
    # still running — streaming nothing. The earlier run is registered again instead.
    _lat_go1, _lat_go2, _lat_b1, _lat_b2 = (_lat_thr.Event() for _ in range(4))
    _lat_t1 = _lat_thr.Thread(target=_lat_worker, args=(_lat_b1, _lat_go1))
    _lat_t1.start()
    _lat_b1.wait(10)
    _lat_first = _ao.get(gs_id)
    _lat_t2 = _lat_thr.Thread(target=_lat_worker, args=(_lat_b2, _lat_go2))
    _lat_t2.start()
    _lat_b2.wait(10)
    _lat_go2.set()
    join_for(_lat_t2, 10)                              # the LATER run finishes first
    _lat_back = _ao.get(gs_id)
    _lat_go1.set()
    join_for(_lat_t1, 10)
    check("console tail: when the later run ends first, the earlier one still running is tailed again",
          _lat_first is not None and _lat_back is _lat_first,
          "after the second validate ended, %r was registered (the first run's entry was %r)"
          % (_lat_back, _lat_first))
    check("console tail: ...and once both have ended nothing is left registered",
          gs_id not in _ao, "left %r registered" % (_ao.get(gs_id),))
    # How an action that the TRANSPORT gave up on is announced. The local and Tailscale
    # transports answer a timeout with rc -1 (they do not raise), and so does paramiko's
    # silent-channel give-up; only a raise leaves rc None. -1 is never a real exit status.
    _lat_end = {}
    with app.app_context():
        for _lat_rc in (None, -1, 2, 0):
            _lat_seen.clear()
            _begin_action_tail(app, gs_id, "update", _lat_logf, _lat_user)
            _end_action_tail(app, gs_id, _lat_remote, "update", _lat_rc)
            _lat_end[_lat_rc] = " ".join(p.get("data") or "" for (e, p, r) in _lat_seen
                                         if e == "console_output")
    check("console tail: a transport timeout (rc -1) is 'stopped reporting', not 'failed'",
          "stopped reporting" in _lat_end[-1] and "failed" not in _lat_end[-1],
          "said %r — an update still running on the host was declared failed" % _lat_end[-1])
    check("console tail: ...as a raised call (rc None) already was",
          "stopped reporting" in _lat_end[None], _lat_end[None])
    check("console tail: ...while a real non-zero exit is still a failure, and 0 a success",
          "failed (exit 2)" in _lat_end[2] and "finished successfully" in _lat_end[0],
          "2=%r 0=%r" % (_lat_end[2], _lat_end[0]))
    check("console tail: ...and the action that owns the entry still clears it (positive control)",
          not _lat_after_own,
          "still registered: %r — the poller would tail a finished action forever, so the "
          "check above would pass with the pop removed altogether" % (_lat_after_own,))

    # 3. The CALLER. Every assertion above passes just as well with a drain nothing invokes —
    # which is exactly the shape of the original bug. So drive the real console poller: give
    # it a viewer, register an action, and wait for the bytes to come out of it.
    _lat_seen.clear()
    _lat_file["text"] = "SteamCMD: validating\n"
    with _r_sf._viewers_lock:
        # {sid: user_id} now — the poller re-checks each viewer's access every tick,
        # so a viewer entry has to say WHOSE socket it is. None means "unknown", which
        # the re-check treats as not-allowed; this block is about the action tail, so
        # give it the seeded admin so it is not evicted mid-test.
        _r_sf._console_viewers.setdefault(gs_id, {})["test-sid"] = admin_id
    try:
        _begin_action_tail(app, gs_id, "validate", _lat_logf, _lat_user)
        _lat_seen.clear()
        _lat_polled = []
        _dl = _pt.time() + 8.0
        while _pt.time() < _dl and not _lat_polled:
            _lat_polled = [p.get("data") for (e, p, r) in _lat_seen
                           if e == "console_output" and "validating" in (p.get("data") or "")]
            _pt.sleep(0.05)
        check("console poller: it drains a running action's output on its own ticks",
              bool(_lat_polled), "the poller never sent it: %s" % _lat_seen)
    finally:
        _ao.pop(gs_id, None)
        with _r_sf._viewers_lock:
            _r_sf._console_viewers.pop(gs_id, None)
finally:
    app.socketio.emit = _lat_sio_saved
    (_sm_core.run_as_game_user, _sm_core.run_command) = _lat_saved
    _ao.clear()

# ── The sweep prunes even when the last host is gone ───────────────────────────────────────
# _forget_deleted_rows is what keeps every row-keyed map honest, and it was the LAST statement
# in _monitor_pass — after `if not remotes: return`. So in the one state where it has the most
# to forget (every host deleted) it never ran at all, and the next host added takes id 1 again
# and inherits the lot. Driven with an empty host list, which is exactly that state.
from panel.services import monitoring as _mp_mon
from panel.core import panel_state as _mp_ps
_mp_saved = _mp_mon.RemoteServer


class _NoRemotes:
    class query:
        @staticmethod
        def all():
            return []


try:
    with app.app_context():
        _mp_mon._player_counts[91919] = {"count": 3, "max": 8, "name": "ghost", "ts": 0}
        _mp_ps._max_players_cache[91919] = 64
        _mp_mon.RemoteServer = _NoRemotes
        _mp_mon._monitor_pass()
    check("monitor sweep: it still forgets deleted rows when NO hosts are left",
          91919 not in _mp_mon._player_counts and 91919 not in _mp_ps._max_players_cache,
          "left: counts=%s max=%s" % (91919 in _mp_mon._player_counts,
                                      91919 in _mp_ps._max_players_cache))
finally:
    _mp_mon.RemoteServer = _mp_saved
    _mp_mon._player_counts.pop(91919, None)
    _mp_ps._max_players_cache.pop(91919, None)

# ── a JSON field of the wrong TYPE is a bad request, not a panel fault ─────────────────────
# _json_body guarantees the BODY is a dict and says nothing about the VALUES, so two dozen
# handlers read `(body.get(k) or "").strip()` — safe against a missing key, and an
# AttributeError on {"command": 5}. Every one answered 500 with "Something went wrong — see
# the panel log", which is the panel accusing itself of a bug the caller caused, and which
# makes 5xx alerting fire on a malformed request. Driven as a superadmin against every
# mutating JSON endpoint the review named, with a NUMBER where a string belongs.
# ── what the ban-watcher RECORDS, and at what threshold ──────────────────────────────────
# The false notifications were half of what the unreadable-jail bug produced: an "IP banned on
# the panel login" message per live ban, then a "Login attack in progress" alert once three
# arrived together. _f2b_ban_events decides; this is what it emits, driven directly rather
# than through the daemon thread.
_fre = sys.modules["app"]   # loaded by `from app import` above
from panel.db.models import AuditLog as _fre_AL
_fre_notes = []
_fre_saved = _fre.notifications.notify
try:
    _fre.notifications.notify = lambda ev, title, body, **k: _fre_notes.append((ev, title))
    with app.app_context():
        _n_before = _fre_AL.query.filter(_fre_AL.action.in_(
            ("fail2ban_ban", "fail2ban_unban"))).count()
    _fre._f2b_record_events(app, (), ())
    with app.app_context():
        _n_noop = _fre_AL.query.filter(_fre_AL.action.in_(
            ("fail2ban_ban", "fail2ban_unban"))).count()
    check("ban watcher: a tick with no events writes nothing and notifies nobody",
          _n_noop == _n_before and not _fre_notes, "rows %d->%d notes=%r"
          % (_n_before, _n_noop, _fre_notes))
    # Two bans is under the spike threshold: audit rows and per-IP notices, no attack alert.
    _fre._f2b_record_events(app, ("203.0.113.1", "203.0.113.2"), ("203.0.113.9",))
    with app.app_context():
        _bans = _fre_AL.query.filter_by(action="fail2ban_ban").count()
        _unbans = _fre_AL.query.filter_by(action="fail2ban_unban").count()
    check("ban watcher: real events are audited, bans and unbans alike",
          _bans >= 2 and _unbans >= 1, "bans=%d unbans=%d" % (_bans, _unbans))
    check("ban watcher: ...with one notice per banned IP",
          [e for e, _t in _fre_notes].count("ip_banned") == 2, repr(_fre_notes))
    check("ban watcher: ...and no attack alert below the spike threshold",
          "ban_spike" not in [e for e, _t in _fre_notes], repr(_fre_notes))
    # ...and at the threshold it fires exactly once.
    _fre_notes.clear()
    _fre._f2b_record_events(
        app, tuple("203.0.113.%d" % i for i in range(20, 20 + _fre._BAN_SPIKE_THRESHOLD)), ())
    check("ban watcher: a burst at the threshold raises one attack alert",
          [e for e, _t in _fre_notes].count("ban_spike") == 1, repr(_fre_notes))
finally:
    _fre.notifications.notify = _fre_saved

# ── the auto-block SETTINGS survive a host read that failed ───────────────────────────────
# They come from config.json, not from the host, and they were inside the same try as the IP
# read — so an exception answered {"ips": [], "error": ...} with no `autoblock` key, the card
# repainted its toggle from the missing value (`!!(d && d.autoblock)`) and showed OFF, and
# saveThreshold reads that toggle back "to preserve the on/off state". One failed read plus
# one Save turned auto-blocking off on a host that had it on.
import panel.ops.system_ops as _so_ab
_ab_saved = _so_ab.fail2ban_top_ips
try:
    _so_ab.fail2ban_top_ips = lambda *a, **k: (_ for _ in ()).throw(OSError("log unreadable"))
    _abj = (c.get("/api/panel/security/top-ips").get_json() or {})
    check("security card: a failed offender read still reports the auto-block setting",
          "autoblock" in _abj and "threshold" in _abj, str(_abj)[:160])
    check("security card: ...and says the log was unreadable rather than showing no activity",
          bool(_abj.get("error") or _abj.get("unreadable")), str(_abj)[:160])
    # None (the reader's "I could not read") is the same answer, without an exception.
    _so_ab.fail2ban_top_ips = lambda *a, **k: None
    _abj2 = (c.get("/api/panel/security/top-ips").get_json() or {})
    check("security card: a None offender read is flagged unreadable, not 'no activity'",
          _abj2.get("unreadable") is True and "autoblock" in _abj2, str(_abj2)[:160])
    # positive control: a real read still answers with the list and the settings.
    _so_ab.fail2ban_top_ips = lambda *a, **k: [{"ip": "203.0.113.5", "attempts": 3, "bans": 1}]
    _abj3 = (c.get("/api/panel/security/top-ips").get_json() or {})
    check("security card: a real read reports the offenders and is not flagged unreadable",
          len(_abj3.get("ips") or []) == 1 and not _abj3.get("unreadable")
          and "autoblock" in _abj3, str(_abj3)[:160])
finally:
    _so_ab.fail2ban_top_ips = _ab_saved

# ── the Security tab's event times say they are UTC ───────────────────────────────────────
# AuditLog.timestamp is naive UTC and remote_manage.js renders it with `new Date(e.time)`,
# which reads an ISO date-time with no offset as the VIEWER's local time — every event was
# shown shifted by the viewer's UTC offset.
from datetime import datetime as _sev_dt
from panel.db.models import AuditLog as _sev_AL  # pylint: disable=reimported
with app.app_context():
    db.session.add(_sev_AL(action="login_failed", username="sev-probe", target="sev-probe",
                           timestamp=_sev_dt(2026, 9, 30, 14, 0, 0)))
    db.session.commit()
_sev = [e for e in ((c.get("/api/panel/security/events").get_json() or {}).get("events") or [])
        if e.get("user") == "sev-probe"]
check("security events: each time carries its UTC marker, so the browser does not read it "
      "as local time", [e.get("time") for e in _sev] == ["2026-09-30T14:00:00Z"], repr(_sev))

# The remote route is the same code with a different reader, and it had the same bug — so it
# gets the same check rather than being taken on the strength of the panel-host one passing.
import panel.routes.remote_security as _rs_ab
_rs_saved = _rs_ab.remote_fail2ban_top_ips
try:
    _rs_ab.remote_fail2ban_top_ips = lambda *a, **k: None
    _rabj = (c.get("/api/remote/%d/security/top-ips" % remote_id).get_json() or {})
    check("security card (remote): an unreadable log still reports the auto-block setting",
          "autoblock" in _rabj and _rabj.get("unreadable") is True, str(_rabj)[:160])
    _rs_ab.remote_fail2ban_top_ips = lambda *a, **k: [{"ip": "203.0.113.9", "attempts": 1}]
    _rabj2 = (c.get("/api/remote/%d/security/top-ips" % remote_id).get_json() or {})
    check("security card (remote): a real read is not flagged unreadable (positive control)",
          len(_rabj2.get("ips") or []) == 1 and not _rabj2.get("unreadable"), str(_rabj2)[:160])
finally:
    _rs_ab.remote_fail2ban_top_ips = _rs_saved

_typed = [
    ("/api/command/%d" % gs_id, {"command": 5}),
    ("/api/server/%d/action" % gs_id, {"action": 5}),
    ("/api/servers/bulk-action", {"action": 5, "ids": [gs_id]}),
    ("/api/server/%d/query-type" % gs_id, {"query_type": 5}),
    ("/api/server/%d/moderate" % gs_id, {"action": 5}),
    ("/api/server/%d/alerts" % gs_id, {"values": 5}),
    ("/api/server/%d/config" % gs_id, {"raw": 5}),
    ("/api/server/%d/mods" % gs_id, {"action": "install", "mod": 5}),
    ("/api/tags", {"name": 5}),
    ("/api/panel/security/block", {"ip": 5}),
    ("/api/panel/security/whitelist", {"ip": 5, "action": "add"}),
    ("/api/panel/backup/delete", {"name": 5}),
    ("/api/panel/backup/full", {"mode": 5}),
    ("/api/remote/%d/security/block" % remote_id, {"ip": 5}),
    ("/api/remote/%d/security/unban" % remote_id, {"jail": 5, "ip": 5}),
    ("/api/remote/%d/pro-service" % remote_id, {"service": 5, "action": 5}),
    ("/api/remote/%d/tailscale-bootstrap" % remote_id, {"auth_key": 5}),
    ("/api/tailscale/check-peer", {"host": 5}),
    ("/api/remote/%d/import" % remote_id, {"servers": [{"user": "u", "game_type": 5}]}),
    ("/api/notifications/test", {"channel": 5}),
]
_typed_500, _typed_404 = [], []
# Hold the backup lock across the sweep. /api/panel/backup/full is in the list and a POST to
# it STARTS A REAL FULL BACKUP — a thread that outlives this block, walks every installed
# server, and calls run_game_backup on whatever that name points at by the time it gets
# there. It landed inside the per-server-retention test 1400 lines below, which stubs exactly
# that name, and reported the stray call's keep as the one the route had used. Only the
# slowest CI leg was slow enough to show it.
#
# Taken BLOCKING, so this also waits out any earlier straggler instead of racing it. mode is
# read before the lock is consulted, so the type handling under test is still exercised.
from panel.core.panel_state import _full_backup_lock as _typed_lock
import panel.routes.panel_backup as _typed_bkmod
# What a leaked worker DOES, recorded — not whether the lock happens to be held when asked.
# The first version of this check polled the lock, and a full backup of one unreachable
# server takes and releases it inside a single 50ms gap: removing the guard below left the
# check green. See a-green-gate-is-not-evidence.
_typed_bkcalls = []
_typed_bkreal = _typed_bkmod.run_game_backup
_typed_bkmod.run_game_backup = lambda *a, **k: (_typed_bkcalls.append(1), (True, "", False))[1]
_typed_lock.acquire(timeout=60)
try:
    for _path, _body in _typed:
        _tr = c.post(_path, json=_body, headers={"X-Requested-With": "XMLHttpRequest"})
        if _tr.status_code >= 500:
            _typed_500.append("%s -> %d" % (_path, _tr.status_code))
        if _tr.status_code == 404:
            _typed_404.append(_path)
finally:
    try:
        _typed_lock.release()
    except RuntimeError:
        pass        # the acquire timed out; nothing of ours to release
# Settle: a worker the sweep started returns from the route before it reaches the backup.
for _ in range(40):
    if _typed_bkcalls:
        break
    _ijw_time.sleep(0.05)
_typed_bkmod.run_game_backup = _typed_bkreal
check("typed body: %d endpoints were driven, so this is not an empty sweep" % len(_typed),
      len(_typed) >= 20, "the list shrank — the check below would prove less")
# ...and every one of them REACHES a handler. This list had "/notifications/test" while the
# route is "/api/notifications/test", so Flask answered 404 — which is < 500, so the sweep
# passed, and the count above reported it as driven. The endpoint's body was entered by
# nothing in the suite while looking covered. Counting the LIST proves the list is long; only
# this proves the paths still resolve, which is what a future rename would break.
check("typed body: ...and every path in that list actually resolves to a route",
      not _typed_404,
      "404 — renamed or mistyped, so the sweep never reached them: %s" % ", ".join(_typed_404))
check("typed body: a number where a string belongs never 500s",
      not _typed_500, "; ".join(_typed_500[:6]))
# ...nor a number that is not one. Python's json reads `Infinity` (and 1e400) as a float, and
# int() of it raises OverflowError — past every `except (TypeError, ValueError)` that parsed an
# id or a port. Each of these answered 500. None of them reaches a host: every id or port here
# is refused before one would be used.
_inf = float("inf")
_inf_bodies = [
    ("/api/servers/bulk-action", {"action": "start", "server_ids": [_inf]}),
    ("/api/server/%d/tags" % gs_id, {"tag_ids": [_inf]}),
    ("/api/account/ui-order", {"host_order": [_inf]}),
    ("/api/remote/%d/firewall/open" % remote_id, {"port": _inf}),
    ("/api/remote/%d/firewall/close" % remote_id, {"port": _inf}),
    ("/api/remote/%d/firewall/limit" % remote_id, {"port": _inf}),
    ("/api/remote/%d/firewall/delete-rule" % remote_id, {"num": _inf}),
    ("/api/remote/%d/ssh-port" % remote_id, {"port": _inf}),
    ("/api/server/%d/config" % gs_id, {"settings": [1]}),
]
_inf_500 = []
for _path, _body in _inf_bodies:
    _ir = c.post(_path, json=_body, headers={"X-Requested-With": "XMLHttpRequest"})
    if _ir.status_code >= 500 or _ir.status_code == 404:
        _inf_500.append("%s -> %d" % (_path, _ir.status_code))
check("typed body: Infinity where an id or port belongs (and a list for a settings map) never "
      "500s", not _inf_500, "; ".join(_inf_500))
# ...and the sweep left nothing running. A POST to /api/panel/backup/full starts a real
# background full backup, and a suite that walks endpoints for validation must not leave one
# RUNNING behind it — that thread outlives this block and calls into whatever the tests below
# have stubbed by the time it gets there. That is what broke CI: it reached the
# per-server-retention test 1400 lines down and was counted as that route's call.
check("typed body: ...and the sweep did not leave a full backup running behind it",
      not _typed_bkcalls,
      "a background backup outlived this block — it walks every server and calls whatever "
      "run_game_backup points at by then, which is a stub in the tests below")

# ── Deleting a user kills the invites they minted ──────────────────────────────────────────
# authority_intact() resolves the creator with db.session.get(User, created_by_id) and fails
# closed when it is gone — "a missing creator fails closed: the row is deleted or the id
# dangles". But user.id is a bare INTEGER PRIMARY KEY, so SQLite hands the freed rowid to the
# very next account created: the creator is then not missing, it is a DIFFERENT PERSON, and
# the check says yes. Offboard an admin, create their replacement, and the dead invite is live
# again — for a superadmin invite as soon as that replacement is promoted, which is exactly
# what happens in that scenario. manage_users lists it as "Active" throughout.
from panel.db.models import Invite as _InvS
with app.app_context():
    _ivu = User(username="smoke_inviter", password_hash=auth.hash_password("Str0ng!passw0rd"),
                is_superadmin=True, is_active=True)
    db.session.add(_ivu)
    db.session.commit()
    _ivu_id = _ivu.id
    _inv_row, _ = _InvS.mint(_ivu, hours=48, superadmin=True)
    db.session.add(_inv_row)
    # ...and an audit entry attributed to them, for the AuditLog half of the same delete.
    db.session.add(_AL(user_id=_ivu_id, username="smoke_inviter", action="login",
                       target="", detail="", success=True))
    db.session.commit()
    _inv_id = _inv_row.id
    check("invite: it is usable while its creator exists",
          _inv_row.is_usable and _inv_row.authority_intact(db.session.get(User, _ivu_id)),
          "the next check would prove nothing otherwise")
    db.session.delete(db.session.get(User, _ivu_id))
    db.session.commit()
    _inv_after = db.session.get(_InvS, _inv_id)
    check("invite: deleting its creator revokes it", _inv_after.revoked_at is not None,
          "revoked_at=%r" % _inv_after.revoked_at)
    check("invite: ...so it is not usable", not _inv_after.is_usable)
    # And prove the resurrection route really is open: take the recycled id deliberately.
    _heir = User(id=_ivu_id, username="smoke_replacement",
                 password_hash=auth.hash_password("Str0ng!passw0rd"),
                 is_superadmin=True, is_active=True)
    db.session.add(_heir)
    db.session.commit()
    check("invite: the replacement account really does take the freed id",
          _heir.id == _ivu_id, "id=%d want=%d" % (_heir.id, _ivu_id))
    check("invite: ...and authority_intact now says YES about a different person",
          _inv_after.authority_intact(db.session.get(User, _ivu_id)) is True,
          "if this ever says False the revocation above is no longer what closes the hole")
    check("invite: ...but the stamped revocation still holds", not _inv_after.is_usable,
          "a rowid cannot undo revoked_at")
    # Same delete, the other dangling pointer: AuditLog.user_id is a FK with no cascade, the
    # app never sets PRAGMA foreign_keys, and the rowid is recycled — so the deleted admin's
    # entries pointed at their replacement. The entries themselves must SURVIVE (username is
    # the auditable fact and is meant to outlive the account); only the pointer must not lie.
    _al_rows = _AL.query.filter_by(username="smoke_inviter").count()
    check("audit: the deleted user's entries are still there", _al_rows >= 1,
          "no rows to check — the next check would pass vacuously")
    check("audit: ...but none of them still points at the recycled id",
          _AL.query.filter_by(user_id=_ivu_id).count() == 0,
          "%d row(s) now resolve to smoke_replacement"
          % _AL.query.filter_by(user_id=_ivu_id).count())
    db.session.delete(db.session.get(_InvS, _inv_id))
    db.session.delete(db.session.get(User, _ivu_id))
    db.session.commit()

# ── ...and deleting a GROUP kills the invites that grant it, for the same reason ────────────
# Invite.group_ids is a JSON list of bare Group.id integers, frozen at mint time and resolved
# at redemption purely by id — and Group.id is the same bare INTEGER PRIMARY KEY with the same
# rowid recycling. Nothing downstream catches it: redeem_invite's group re-check is guarded by
# `if _creator is not None and not _creator.is_superadmin`, and minting is @superadmin_required,
# so for a creator who is still a superadmin the check is skipped and user.groups is assigned
# from whatever rows hold those ids now. Driven with the freed id taken deliberately, the same
# way the user half above proves its own resurrection route is open.
with app.app_context():
    _gi_creator = User.query.filter_by(is_superadmin=True).first()
    _gi_grp = Group(name="smoke_trial_group", description="smoke (auto)", is_default=False)
    _gi_grp.set_permissions([auth.VIEW_SERVERS])
    db.session.add(_gi_grp)
    db.session.commit()
    _gi_gid = _gi_grp.id
    _gi_inv, _ = _InvS.mint(_gi_creator, hours=48, group_ids=[_gi_gid])
    db.session.add(_gi_inv)
    db.session.commit()
    _gi_iid = _gi_inv.id
    check("invite: it is usable while the group it grants exists",
          _gi_inv.is_usable and _gi_inv.groups_wanted == [_gi_gid],
          "the next check would prove nothing otherwise")
    db.session.delete(db.session.get(Group, _gi_gid))
    db.session.commit()
    _gi_after = db.session.get(_InvS, _gi_iid)
    check("invite: deleting a group it grants revokes it",
          _gi_after.revoked_at is not None, "revoked_at=%r" % _gi_after.revoked_at)
    check("invite: ...so it is not usable", not _gi_after.is_usable)
    # The resurrection route really is open: take the freed rowid with a group that grants far
    # more than the deleted one did.
    _gi_heir = Group(id=_gi_gid, name="smoke_server_owners", description="smoke (auto)",
                     is_default=False)
    _gi_heir.set_permissions([auth.MANAGE_USERS, auth.MANAGE_REMOTES, auth.MANAGE_SERVERS])
    db.session.add(_gi_heir)
    db.session.commit()
    check("invite: the replacement group really does take the freed id",
          _gi_heir.id == _gi_gid, "id=%d want=%d" % (_gi_heir.id, _gi_gid))
    check("invite: ...but the stamped revocation still holds", not _gi_after.is_usable,
          "a rowid cannot undo revoked_at")
    # Positive control: an invite that names OTHER groups is untouched by the delete, so the
    # listener is a targeted revoke and not a blanket one.
    _gi_keep = Group(name="smoke_keep_group", description="smoke (auto)", is_default=False)
    _gi_keep.set_permissions([auth.VIEW_SERVERS])
    db.session.add(_gi_keep)
    db.session.commit()
    _gi_keep_id = _gi_keep.id
    _gi_doomed = Group(name="smoke_doomed_group", description="smoke (auto)", is_default=False)
    _gi_doomed.set_permissions([auth.VIEW_SERVERS])
    db.session.add(_gi_doomed)
    db.session.commit()
    _gi_bystander, _ = _InvS.mint(_gi_creator, hours=48, group_ids=[_gi_keep_id])
    db.session.add(_gi_bystander)
    db.session.commit()
    _gi_by_id = _gi_bystander.id
    db.session.delete(db.session.get(Group, _gi_doomed.id))
    db.session.commit()
    check("invite: deleting an unrelated group leaves other invites alone",
          db.session.get(_InvS, _gi_by_id).is_usable,
          "a targeted revoke turned into a blanket one")
    db.session.delete(db.session.get(_InvS, _gi_iid))
    db.session.delete(db.session.get(_InvS, _gi_by_id))
    db.session.delete(db.session.get(Group, _gi_gid))
    db.session.delete(db.session.get(Group, _gi_keep_id))
    db.session.commit()

# ── Deleting a host forgets everything keyed on its id ─────────────────────────────────────
# SQLite hands a deleted row's id straight to the next INSERT, and delete_remote is the one
# route that removes a host — taking its game servers with it, without uninstall_server ever
# running. Three kinds of state were left behind:
#
#   * config["autoblock_hosts"] — a LIST OF REMOTE IDS, persisted, so a restart does not clear
#     it. The hourly sweep looks each id up; once it is live again that is the NEW host, and
#     the panel starts adding `ufw deny` rules to a machine nobody enabled auto-blocking on.
#   * config["game_schedules"] — per-server backup overrides, keyed by game-server id.
#     uninstall_server already removes these deliberately; the cascade never did.
#   * ssh_manager's per-remote caches. _specs_cache has NO expiry, so a recycled id reported
#     the deleted machine's CPU/RAM/disk/OS until the panel restarted.
with app.app_context():
    _dr_remote = RemoteServer(name="smoke-delhost", host="127.0.0.1", port=22,
                              username="root", auth_method="key", auth_credential="")
    db.session.add(_dr_remote)
    db.session.flush()
    _dr_gs = GameServer(remote_id=_dr_remote.id, name="smoke-delgame",
                        short_name="delgameserver", game_type="csgo", port=27099,
                        installed=True, status="offline")
    db.session.add(_dr_gs)
    db.session.commit()
    _dr_rid, _dr_gid = _dr_remote.id, _dr_gs.id
from panel.core.config import load_config as _dr_cfg, update_config as _dr_upd
from panel.ops import backup as _dr_bk
from panel.ops.ssh_manager import _core as _dr_core, firewall as _dr_fw, hosts as _dr_hosts
_dr_upd(lambda c: c.__setitem__("autoblock_hosts",
                                sorted(set(c.get("autoblock_hosts") or []) | {_dr_rid})))
_dr_bk.set_game_schedule(_dr_gid, 3, 2)
# ...and a metric sample for that game server. _prune_host_game_samples listens on
# RemoteServer's after_delete and deletes by `server_id IN (SELECT id FROM game_server WHERE
# remote_id = ...)` — but delete_remote BULK-deletes the game servers first, so by the time it
# fires the subquery matches nothing. Both rowids are then recycled and the next server created
# serves the deleted one's history on /api/server/<id>/history for the 14-day prune window.
from panel.db.models import MetricSample as _dr_MS
from panel.core.clock import utcnow as _utcnow_mon
with app.app_context():
    db.session.add(_dr_MS(server_id=_dr_gid, ts=_utcnow_mon(),
                          cpu=99.0, ram_mb=512, players=7))
    db.session.commit()
    _dr_samples_before = _dr_MS.query.filter_by(server_id=_dr_gid).count()
check("delete host: the sample fixture armed", _dr_samples_before >= 1,
      "no MetricSample row — the check after the delete would pass vacuously")
# ...and a saved LAYOUT position for both. ui_prefs holds host_order (remote ids) and
# server_order ({remote_id: [server id]}), and nothing cleared them — so after the rowid is
# recycled a brand-new host or server inherited the deleted one's slot in every user's
# dashboard, for every user who had ever reordered.
with app.app_context():
    _dr_u = User.query.filter_by(username="smoke_admin").first()
    _dr_u.set_ui_pref("host_order", [_dr_rid, 99999])
    _dr_u.set_ui_pref("server_order", {str(_dr_rid): [_dr_gid]})
    db.session.commit()
    _dr_prefs_before = _dr_u.get_ui_prefs()
check("delete host: the layout fixture armed",
      _dr_rid in (_dr_prefs_before.get("host_order") or []),
      "no saved order — the check after the delete would pass vacuously")
_dr_fw._specs_cache[_dr_rid] = {"os": "deleted host"}
_dr_hosts._pro_status_cache[_dr_rid] = (9e18, {"attached": True})
_dr_core._gamedig_host_cache[_dr_rid] = (9e18, "203.0.113.9")
check("delete host: the fixtures really armed (autoblock + schedule + caches)",
      _dr_rid in (_dr_cfg().get("autoblock_hosts") or [])
      and str(_dr_gid) in (_dr_cfg().get("game_schedules") or {})
      and _dr_rid in _dr_fw._specs_cache,
      "autoblock=%s schedules=%s" % (_dr_cfg().get("autoblock_hosts"),
                                     list((_dr_cfg().get("game_schedules") or {}))))
# ...and a FAILED install job for that server, exactly as _run_install_job leaves one. This is
# the half that is visible to a user: the monitor's sweep prunes it, but only on its next pass,
# so until then /api/server/<id>/install-status answers for whatever server takes the freed row
# id with the DELETED one's failure. Driven end to end below rather than asserted from the map.
from panel.core.panel_state import _install_jobs as _dr_jobs, _install_lock as _dr_jlock
with _dr_jlock:
    _dr_jobs[_dr_gid] = {"status": "failed", "step": 3, "total": 8, "step_name": "Downloading",
                         "message": "SteamCMD could not log in", "log": ["boom"],
                         "started": _pt.time(), "updated": _pt.time(), "name": "smoke-delgame"}
_dr_resp = c.post("/remotes/%d/delete" % _dr_rid, json={"password": "Str0ng!passw0rd"},
                  headers={"X-Requested-With": "XMLHttpRequest"})
check("delete host: the request succeeds",
      (_dr_resp.get_json() or {}).get("success") is True,
      "%d %s" % (_dr_resp.status_code, _dr_resp.get_data(as_text=True)[:120]))
_dr_after = _dr_cfg()
check("delete host: its auto-block opt-in is gone from config (a reused id would inherit it)",
      _dr_rid not in (_dr_after.get("autoblock_hosts") or []),
      "still listed: %s" % (_dr_after.get("autoblock_hosts"),))
check("delete host: its game server's backup schedule is gone from config too",
      str(_dr_gid) not in (_dr_after.get("game_schedules") or {}),
      "still present: %s" % (list(_dr_after.get("game_schedules") or {}),))
with app.app_context():
    _dr_samples_after = _dr_MS.query.filter_by(server_id=_dr_gid).count()
with app.app_context():
    _dr_prefs_after = User.query.filter_by(username="smoke_admin").first().get_ui_prefs()
check("delete host: it is gone from every saved dashboard order",
      _dr_rid not in (_dr_prefs_after.get("host_order") or [])
      and str(_dr_rid) not in (_dr_prefs_after.get("server_order") or {}),
      "still placed: %s / %s" % (_dr_prefs_after.get("host_order"),
                                 list(_dr_prefs_after.get("server_order") or {})))
check("delete host: ...while another user's unrelated entries are left alone",
      99999 in (_dr_prefs_after.get("host_order") or []),
      "the sweep removed more than the deleted host: %s" % (_dr_prefs_after.get("host_order"),))
check("delete host: its game servers' metric history goes with it",
      _dr_samples_after == 0,
      "%d sample(s) left — a recycled server id would serve the deleted one's history"
      % _dr_samples_after)
# Named individually, NOT walked off _core._remote_caches: iterating the registry makes this
# pass vacuously the moment a cache stops being registered — which is the exact regression it
# is here to catch. (Verified: it passed against an unregistered build before this changed.)
_dr_stale = [n for n, _m in (("host specs", _dr_fw._specs_cache),
                             ("ubuntu pro", _dr_hosts._pro_status_cache),
                             ("gamedig host", _dr_core._gamedig_host_cache))
             if _dr_rid in _m]
check("delete host: the per-remote SSH caches forgot it",
      not _dr_stale, "still cached by: %s" % ", ".join(_dr_stale))
# The row id is now free. Re-create a server — SQLite hands it straight back — and ask the
# endpoint about the NEW one. Anything but "none" is the deleted server's job answering.
with app.app_context():
    _dr_r2 = RemoteServer(name="smoke-freshhost", host="127.0.0.1", port=22, username="root",
                          auth_method="key", auth_credential="")
    db.session.add(_dr_r2)
    db.session.flush()
    _dr_gs2 = GameServer(remote_id=_dr_r2.id, name="smoke-brandnew", short_name="newgameserver",
                         game_type="gmod", port=27098, installed=True, status="offline")
    db.session.add(_dr_gs2)
    db.session.commit()
    _dr_gid2, _dr_rid2 = _dr_gs2.id, _dr_r2.id
_dr_is = c.get("/api/server/%d/install-status" % _dr_gid2).get_json() or {}
check("delete host: a server reusing the freed id does NOT inherit its install outcome",
      _dr_is.get("status") == "none",
      "id reused=%s, install-status=%r" % (_dr_gid2 == _dr_gid, _dr_is))
with app.app_context():                       # tidy up
    for _m, _i in ((GameServer, _dr_gid2), (RemoteServer, _dr_rid2)):
        _row = db.session.get(_m, _i)
        if _row:
            db.session.delete(_row)
    db.session.commit()
with _dr_jlock:
    _dr_jobs.pop(_dr_gid, None)
    _dr_jobs.pop(_dr_gid2, None)

# ── join_console and leave_console must agree on the KEY ────────────────────────────────
# The viewer registry is what the console poller iterates: an id left in it costs an SSH round
# trip every two seconds for a console nobody is watching. join_console coerces the id to int
# before using it — deliberately, and with a comment saying why the room name and the map key
# have to be the same value — and leave_console did not, so a client that spelled the id as a
# string left the ROOM (the f-string reads the same either way) and left its sid behind in the
# map. Only a socket disconnect cleaned that up.
#
# Driven through the real socket, not by calling the handler: the coercion only matters
# because a client chooses the spelling, and that is the half a direct call cannot exercise.
_sio_err = ""
try:
    _sio_c = app.socketio.test_client(app, flask_test_client=client_as(admin_id))
    _sio_ok = _sio_c.is_connected()
except Exception as _e:                      # never a silent skip — a gate that cannot run failed
    _sio_c, _sio_ok, _sio_err = None, False, "%s: %s" % (type(_e).__name__, _e)
check("console socket: an authenticated test client connects", _sio_ok, _sio_err)
if _sio_ok:
    try:
        with _r_sf._viewers_lock:
            _r_sf._console_viewers.pop(gs_id, None)
        _sio_c.emit("join_console", {"server_id": gs_id})
        check("console socket: joining registers the viewer",
              bool(_r_sf._console_viewers.get(gs_id)),
              "viewers=%r" % (_r_sf._console_viewers.get(gs_id),))
        _sio_c.emit("leave_console", {"server_id": str(gs_id)})   # the string spelling
        check("console socket: leaving deregisters it however the id was spelled",
              not _r_sf._console_viewers.get(gs_id),
              "left behind: %r" % (_r_sf._console_viewers.get(gs_id),))

        # ── access is re-checked while the socket is OPEN ─────────────────────────────────
        # The join handler's check was the only one. After it passed, the poller streamed to
        # the room for as long as the browser stayed connected, so revoking a group, dropping
        # a permission or deactivating the account did not stop console output already
        # flowing. _evict_unauthorized_viewers is what the poller calls each tick.
        with _r_sf._viewers_lock:
            _r_sf._console_viewers[gs_id] = {"still-allowed": admin_id,
                                             "gone-user": 10 ** 7,   # no such row
                                             "unknown-user": None}
        with app.app_context():
            _n_dropped = _r_sf._evict_unauthorized_viewers(app, app.socketio, gs_id)
        _left = dict(_r_sf._console_viewers.get(gs_id) or {})
        check("console socket: a viewer whose account no longer exists is dropped mid-stream",
              "gone-user" not in _left and "unknown-user" not in _left,
              "still watching: %r" % (_left,))
        check("console socket: ...and the viewer who still qualifies is left alone",
              "still-allowed" in _left, "still watching: %r" % (_left,))
        check("console socket: ...and it reports how many it dropped",
              _n_dropped == 2, "dropped=%r" % (_n_dropped,))
        # ...and when the last qualifying viewer goes, the entry goes with it, so the poller
        # stops SSH-ing at the host on nobody's behalf.
        with app.app_context():
            _r_sf._console_viewers[gs_id] = {"gone-user": 10 ** 7}
            _r_sf._evict_unauthorized_viewers(app, app.socketio, gs_id)
        check("console socket: ...and an emptied console stops being polled at all",
              not _r_sf._console_viewers.get(gs_id),
              "left behind: %r" % (_r_sf._console_viewers.get(gs_id),))
        # A re-check that THREW must not evict. This runs every couple of seconds against the
        # database; a transient failure that dropped every viewer would turn a blip into
        # "the console stopped working", which is worse than the revocation being a tick late.
        # Unknown is not "revoked" — the same asymmetry the rest of this codebase applies to a
        # failed read, pointed the other way because here the safe answer is to keep serving.
        _acs_saved = _r_sf.can_access_server
        try:
            def _acs_boom(_user, _sid):
                raise OSError("the database did not answer")

            _r_sf.can_access_server = _acs_boom
            with _r_sf._viewers_lock:
                _r_sf._console_viewers[gs_id] = {"still-allowed": admin_id}
            with app.app_context():
                _n_boom = _r_sf._evict_unauthorized_viewers(app, app.socketio, gs_id)
            check("console socket: a re-check that failed keeps the viewer, it does not evict",
                  _n_boom == 0 and "still-allowed" in (_r_sf._console_viewers.get(gs_id) or {}),
                  "dropped=%r left=%r" % (_n_boom, _r_sf._console_viewers.get(gs_id)))
        finally:
            _r_sf.can_access_server = _acs_saved
            with _r_sf._viewers_lock:
                _r_sf._console_viewers.pop(gs_id, None)
    finally:
        with _r_sf._viewers_lock:
            _r_sf._console_viewers.pop(gs_id, None)
        try:
            _sio_c.disconnect()
        except Exception:
            pass  # a client the server already dropped has nothing left to close

# ── ...and so is the CREDENTIAL the socket joined with ───────────────────────────────────
# The per-tick re-check asked only about the user ROW. None of the panel's revocation controls
# change the row's answers: a device revoke deletes a UserSession row, "sign out everywhere"
# bumps auth_epoch, revoking an API token clears its hash. load_user enforces all of them on
# every socket EVENT — but the console is push-only, so after join_console nothing re-ran it,
# and a stolen cookie that had been signed out everywhere kept receiving the console.
import hashlib as _cv_hl
from panel.db.models import UserSession as _CvUS
with app.app_context():
    _cv_u = db.session.get(User, admin_id)
    _cv_saved = (_cv_u.auth_epoch, _cv_u.api_token, _cv_u.must_change_password)
    db.session.add(_CvUS(user_id=admin_id, sid="smoke_console_sid", ip="", user_agent=""))
    db.session.commit()
    _cv_login = "%d:%d:smoke_console_sid" % (admin_id, _cv_u.auth_epoch or 0)


def _cv_socket(**hdr):
    _fc = app.test_client()
    if not hdr:
        with _fc.session_transaction() as _ss:
            _ss["_user_id"] = _cv_login
            _ss["_fresh"] = True
    _c = app.socketio.test_client(app, flask_test_client=_fc, headers=hdr or None)
    with _r_sf._viewers_lock:
        _r_sf._console_viewers.pop(gs_id, None)
    _c.emit("join_console", {"server_id": gs_id})
    _vsid = next(iter(_r_sf._console_viewers.get(gs_id) or {}), None)
    _cv_sids.append(_vsid)
    return _c, _vsid


def _cv_evict():
    with app.app_context():
        _r_sf._evict_unauthorized_viewers(app, app.socketio, gs_id)
    return bool(_r_sf._console_viewers.get(gs_id))


_cv_clients, _cv_sids = [], []
try:
    # A cookie tied to one UserSession row: revoking that device must end the stream.
    _cv_c, _cv_sid = _cv_socket()
    _cv_clients.append(_cv_c)
    check("console socket: a session-cookie viewer joins, and its login id is recorded",
          _cv_sid is not None and (_r_sf._viewer_creds.get(_cv_sid) or ("",))[0] == _cv_login,
          "viewer=%r cred=%r" % (_cv_sid, _r_sf._viewer_creds.get(_cv_sid)))
    check("console socket: ...and the re-check keeps it while that login stands (control)",
          _cv_evict(), "a valid viewer was evicted")
    with app.app_context():
        _CvUS.query.filter_by(sid="smoke_console_sid").delete()
        db.session.commit()
    check("console socket: revoking the viewer's DEVICE ends the stream at the next tick",
          not _cv_evict(), "the socket of a revoked session is still being streamed to")

    # "Sign out everywhere" / a password change: the epoch moves, every cookie stops matching.
    with app.app_context():
        db.session.add(_CvUS(user_id=admin_id, sid="smoke_console_sid", ip="", user_agent=""))
        db.session.commit()
    _cv_c, _cv_sid = _cv_socket()
    _cv_clients.append(_cv_c)
    check("console socket: (control) a fresh viewer is kept before the epoch moves",
          _cv_evict(), "a valid viewer was evicted")
    with app.app_context():
        db.session.get(User, admin_id).auth_epoch = (_cv_saved[0] or 0) + 1
        db.session.commit()
    check("console socket: 'sign out everywhere' ends the stream at the next tick",
          not _cv_evict(), "the socket outlived a bumped auth_epoch")
    with app.app_context():
        db.session.get(User, admin_id).auth_epoch = _cv_saved[0]
        db.session.commit()

    # A bearer token: revoking it changes neither the epoch nor any session row.
    with app.app_context():
        db.session.get(User, admin_id).api_token = _cv_hl.sha256(b"smoke-console-token").hexdigest()
        db.session.commit()
    _cv_c, _cv_sid = _cv_socket(Authorization="Bearer smoke-console-token")
    _cv_clients.append(_cv_c)
    check("console socket: (control) a bearer-token viewer joins and is kept while the token "
          "stands", _cv_sid is not None and _cv_evict(),
          "viewer=%r cred=%r" % (_cv_sid, _r_sf._viewer_creds.get(_cv_sid)))
    with app.app_context():
        db.session.get(User, admin_id).api_token = None
        db.session.commit()
    check("console socket: revoking the API TOKEN ends the stream at the next tick",
          not _cv_evict(), "the socket outlived its revoked token")

    # A forced password change is refused at join; the re-check must refuse it too.
    with app.app_context():
        db.session.add(_CvUS(user_id=admin_id, sid="smoke_console_sid2", ip="", user_agent=""))
        db.session.commit()
    _cv_login = "%d:%d:smoke_console_sid2" % (admin_id, _cv_saved[0] or 0)
    _cv_c, _cv_sid = _cv_socket()
    _cv_clients.append(_cv_c)
    with app.app_context():
        db.session.get(User, admin_id).must_change_password = True
        db.session.commit()
    check("console socket: a password reset mid-stream ends it at the next tick",
          _cv_sid is not None and not _cv_evict(),
          "the socket kept streaming to an account held at a forced password change")
    with app.app_context():
        db.session.get(User, admin_id).must_change_password = _cv_saved[2]
        db.session.commit()

    # The re-check must not itself keep the login alive. It ran load_user, a REQUEST hook that
    # writes UserSession.last_seen every ~5 minutes, and idle expiry is measured from
    # last_seen: a login with a console socket open (a stolen remember cookie included) never
    # idled out server-side.
    from datetime import timedelta as _cv_td
    from panel.core.clock import utcnow as _cv_now  # pylint: disable=reimported
    from panel.db.models import session_idle_limits as _cv_limits
    _cv_c, _cv_sid = _cv_socket()     # joining runs load_user itself: age the row AFTER it
    _cv_clients.append(_cv_c)
    _cv_old = (_cv_now() - _cv_td(seconds=400)).replace(microsecond=0)
    with app.app_context():
        _CvUS.query.filter_by(sid="smoke_console_sid2").update({"last_seen": _cv_old})
        db.session.commit()
    _cv_kept = _cv_sid is not None and _cv_evict()
    with app.app_context():
        _cv_seen = _CvUS.query.filter_by(sid="smoke_console_sid2").first().last_seen
    check("console socket: (control) a viewer whose login sat idle 400s is still kept",
          _cv_kept, "viewer=%r" % (_cv_sid,))
    check("console socket: the per-tick re-check does not refresh the login's last_seen",
          _cv_seen == _cv_old, "last_seen %r became %r" % (_cv_old, _cv_seen))

    # "Could not look" is not "revoked". load_user answers a database error with None (deny
    # this request), which the poller read as a revocation: a transient lock evicted a
    # legitimate viewer with "[access to this console was revoked]" until they reloaded.
    from sqlalchemy.exc import OperationalError as _cv_OpErr
    _cv_ie = _CvUS.is_expired

    def _cv_locked(self, now=None):
        raise _cv_OpErr("SELECT", {}, Exception("database is locked"))

    _CvUS.is_expired = _cv_locked
    try:
        _cv_kept_locked = _cv_evict()
    finally:
        _CvUS.is_expired = _cv_ie
    check("console socket: a database error in the credential re-check keeps the viewer",
          _cv_kept_locked, "a viewer was evicted as revoked because the session row could "
          "not be read")

    # ...while a login that HAS idled out still ends the stream (the check that last_seen
    # feeds, so the one a refreshing re-check had disabled).
    with app.app_context():
        _CvUS.query.filter_by(sid="smoke_console_sid2").update(
            {"last_seen": _cv_now() - _cv_td(seconds=max(_cv_limits()) + 60)})
        db.session.commit()
    check("console socket: a login that idled out ends the stream at the next tick",
          not _cv_evict(), "the socket outlived its session's idle expiry")

    # One definition of "still signed in": the side-effect-free check must agree with the
    # request hook on every login id, so a control added to one and not the other shows here.
    with app.app_context():
        db.session.add(_CvUS(user_id=admin_id, sid="smoke_console_sid3", ip="", user_agent=""))
        db.session.commit()
    _cv_ep = _cv_saved[0] or 0
    _cv_cases = ["%d:%d:smoke_console_sid3" % (admin_id, _cv_ep),
                 "%d:%d:smoke_console_nosuch" % (admin_id, _cv_ep),
                 "%d:%d" % (admin_id, _cv_ep),
                 "%d:%d:smoke_console_sid3" % (admin_id, _cv_ep + 1),
                 "%d" % admin_id, "x:0", "%d:0" % (10 ** 7),
                 "%d:%d:smoke_console_sid2" % (admin_id, _cv_ep)]     # idled out, above
    _cv_mismatch, _cv_accepted = [], []
    _cv_load = app.login_manager.user_callback
    for _cv_inactive in (False, True):
        for _cv_lid in _cv_cases:
            with app.test_request_context("/"):
                _cv_u = db.session.get(User, admin_id)
                _cv_u.is_active = not _cv_inactive
                try:
                    _cv_a = _r_sf._login_id_still_accepted(_cv_lid)
                    _cv_b = _cv_load(_cv_lid)
                finally:
                    _cv_u.is_active = True
                    db.session.commit()
                _cv_ida, _cv_idb = getattr(_cv_a, "id", None), getattr(_cv_b, "id", None)
                if _cv_ida != _cv_idb:
                    _cv_mismatch.append((_cv_lid, _cv_inactive, _cv_ida, _cv_idb))
                elif _cv_ida is not None:
                    _cv_accepted.append((_cv_lid, _cv_inactive))
    check("console socket: _login_id_still_accepted and load_user agree on every login id",
          not _cv_mismatch, "disagree (id, inactive, still_accepted, load_user): %r"
          % (_cv_mismatch,))
    check("console socket: (control) ...and both accept exactly the valid ones",
          # The bare "<id>" (4) only while the epoch is still 0: a pre-epoch cookie is one
          # that any epoch bump revoked (auth._load_legacy_user).
          _cv_accepted == [(_cv_cases[i], False) for i in ((0, 2, 4) if _cv_ep == 0 else (0, 2))],
          "accepted by both: %r" % (_cv_accepted,))
finally:
    for _c in _cv_clients:
        try:
            _c.disconnect()
        except Exception:
            pass  # a client the server already dropped has nothing left to close
    with _r_sf._viewers_lock:
        _r_sf._console_viewers.pop(gs_id, None)
    with app.app_context():
        _cv_u = db.session.get(User, admin_id)
        (_cv_u.auth_epoch, _cv_u.api_token, _cv_u.must_change_password) = _cv_saved
        _CvUS.query.filter(_CvUS.sid.in_(["smoke_console_sid", "smoke_console_sid2",
                                           "smoke_console_sid3"])).delete(
            synchronize_session=False)
        db.session.commit()
check("console socket: a disconnect forgets the socket's recorded credential",
      len([k for k in _cv_sids if k is not None]) == 5
      and not any(k in _r_sf._viewer_creds for k in _cv_sids),
      "sids=%r left behind: %r" % (_cv_sids, [k for k in _cv_sids if k in _r_sf._viewer_creds]))

# ── The forced-password-change gate has to be asked ON THE SOCKET ────────────────────────
# must_change_password is enforced by an @app.before_request (app.py), and a before_request
# NEVER runs for a Socket.IO event — flask-socketio's middleware takes /socket.io/ ahead of the
# Flask app. So the whole socket surface sat outside the gate: an account holding a password an
# admin generated, read off a screen and relayed was answered 403 password_change_required by
# every HTTP route in the panel, and could still emit join_console and be streamed that
# server's live console — RCON output, admin commands, player names, connect lines.
# host_terminal's _may_use_terminal asks this question for exactly this reason; the console
# socket did not.
_pw_sio, _pw_new, _pw_before = None, None, None
try:
    _pw_err0 = ""
    try:
        _pw_sio = app.socketio.test_client(app, flask_test_client=client_as(admin_id))
    except Exception as _e:
        _pw_err0 = "%s: %s" % (type(_e).__name__, _e)
    # The control, taken BEFORE the flag is set: this account gets a socket normally, so a
    # refusal below is the flag and not the harness refusing everything.
    check("console socket: (control) the account gets a socket while its password is its own",
          bool(_pw_sio is not None and _pw_sio.is_connected()), _pw_err0)
    with app.app_context():
        _pw_u = db.session.get(User, admin_id)
        _pw_before = _pw_u.must_change_password
        _pw_u.must_change_password = True
        db.session.commit()
    # An ALREADY-OPEN socket: connect does not run a second time, so join_console has to ask
    # as well — this is the socket that was open when the admin reset the password.
    with _r_sf._viewers_lock:
        _r_sf._console_viewers.pop(gs_id, None)
    if _pw_sio is not None and _pw_sio.is_connected():
        _pw_sio.emit("join_console", {"server_id": gs_id})
    check("console socket: an open socket cannot join a console once the account must change "
          "its password",
          not _r_sf._console_viewers.get(gs_id),
          "viewers=%r — the poller streams that console to a session the panel answers 403 "
          "on every other route" % (_r_sf._console_viewers.get(gs_id),))
    # ...and a NEW socket is refused at connect, which is what covers every event on the
    # namespace rather than the handful that remembered to check.
    _pw_conn, _pw_err = True, ""
    try:
        _pw_new = app.socketio.test_client(app, flask_test_client=client_as(admin_id))
        _pw_conn = _pw_new.is_connected()
    except Exception as _e:
        _pw_conn, _pw_err = False, "%s: %s" % (type(_e).__name__, _e)
    check("console socket: ...and a new socket is refused at connect",
          _pw_conn is False,
          "connected — %s" % (_pw_err or "the connect gate admitted an account holding a "
                                         "handed-over temporary password"))
finally:
    if _pw_before is not None:
        with app.app_context():
            db.session.get(User, admin_id).must_change_password = _pw_before
            db.session.commit()
    for _pw_cl in (_pw_sio, _pw_new):
        try:
            if _pw_cl is not None:
                _pw_cl.disconnect()
        except Exception:
            pass  # a client the server already dropped has nothing left to close
    with _r_sf._viewers_lock:
        _r_sf._console_viewers.pop(gs_id, None)

# ── A long action's output survives a reload, and keeps LinuxGSM's colour ────────────────
# Two follow-ups to the tail above, both reported straight after it shipped.
#
# "when you refresh the page after i did update...those messages went away" — and they did.
# The socket reaches only the pages open at the time, and /api/console rebuilds a console by
# tailing the GAME's console log, which a panel action never writes to. So the output existed
# in exactly one place: the DOM of whichever tab happened to be open.
#
# "in putty when i run a linuxgsm command it will show it in color" — LinuxGSM colours its own
# output ([  OK  ] green, [ FAIL ] red) and every display path ran it through strip_escapes,
# which is right for the paths that PARSE this text and wrong for the one showing it to a
# person.
from panel.core.panel_state import _console_backlog as _cb
from panel.routes._shared import (_CONSOLE_BACKLOG_MAX, _console_push)
_cb.clear()
_bl_saved = _sm_core.run_command
# What the panel pushes is NOT a line of the game's console log, and the payload must say so:
# the browser de-duplicates the log by matching its own copy against each /api/console window,
# and a line only the page holds can never match — the first poll after an update found no
# overlap and appended the whole window again beneath "[panel] update finished".
_pf_seen, _pf_emit = [], app.socketio.emit
try:
    app.socketio.emit = lambda ev, payload, **k: _pf_seen.append((ev, payload))
    _console_push(app, gs_id, "[panel] probe line", ts=1700000000.0)
finally:
    app.socketio.emit = _pf_emit
check("console backlog: a panel push is marked as not coming from the console log",
      _pf_seen and _pf_seen[-1][0] == "console_output" and _pf_seen[-1][1].get("panel") is True
      and "rows" not in _pf_seen[-1][1],
      "emitted %r" % (_pf_seen,))
_cb.clear()
try:
    _console_push(app, gs_id, "[panel] update started — its output follows.", ts=1700000000.0)
    _console_push(app, gs_id, "\x1b[32m[  OK  ]\x1b[0m Update complete", ts=1700000042.0)
    check("console backlog: what the panel pushed is remembered, not only broadcast",
          len(_cb.get(gs_id, [])) == 2, "backlog=%s" % (_cb.get(gs_id),))
    # The time rides ALONGSIDE the line, never inside it. The browser stitches its scrollback
    # by matching line strings between overlapping windows of the log, so a timestamp prefixed
    # onto the text would make every line unique and render the whole window twice per poll.
    check("console timestamps: the time is kept beside the line, not prefixed onto it",
          all(r["t"] and "1700000" not in r["line"] for r in _cb[gs_id]),
          "backlog=%s" % (_cb.get(gs_id),))
    check("console timestamps: ...and it is the time the panel actually saw that line",
          [r["t"] for r in _cb[gs_id]] == [1700000000.0, 1700000042.0],
          "times=%s" % [r["t"] for r in _cb[gs_id]])
    # A reload asks /api/console. The host is unreachable in this suite, which is the case
    # that matters most: an update's output is exactly what you still want to read when the
    # server it was updating is down.
    _sm_core.run_command = lambda *a, **k: ("", "", 1)
    _blj = c.get("/api/console/%d" % gs_id).get_json() or {}
    _bl_rows = _blj.get("panel_lines") or []
    check("console backlog: a reload gets it back from /api/console",
          any("update started" in (r.get("line") or "") for r in _bl_rows),
          "panel_lines=%s" % _bl_rows)
    check("console backlog: ...with the times, so a reload keeps them for the ONE source "
          "that has real ones",
          [r.get("t") for r in _bl_rows] == [1700000000.0, 1700000042.0],
          "times=%s" % [r.get("t") for r in _bl_rows])
    check("console backlog: ...in its OWN field, not spliced into the game log's window",
          _blj.get("lines") == [] and "panel_lines" in _blj,
          "lines=%s" % (_blj.get("lines"),))
    # A console the route COULD NOT READ must not be answered as a console that is empty.
    # rc != 0 (the non-raising transports), an exception (paramiko), a log that does not exist
    # and a genuinely empty log all left here as 200 with the same `lines: []`, and nothing in
    # the payload told them apart — so "Load older" emptied the browser's scrollback, which is
    # the only copy of it (the poller emits a sliding window and keeps nothing), and reported
    # "Loaded 0 lines from the log" about a log it never opened.
    check("console read: a console that could not be read says so",
          _blj.get("readable") is False,
          "readable=%r with lines=[] — indistinguishable from a server that has written "
          "nothing" % (_blj.get("readable"),))
    # THE ONE THAT MATTERS MOST, and the one every other check here passes without: the game
    # log's window must carry NO time. Those lines are a fresh tail of a file that records no
    # per-line time for most games — the panel is reading them now but they were written at
    # some unknowable point before that. Stamping them with the read time would put a
    # confident wrong time on a week of history, which is worse than a blank gutter, and it
    # looks exactly right until you notice every old line claims the moment you opened the
    # page. Asserted on a reachable host so `lines` is non-empty and the check has something
    # to be wrong about.
    _sm_core.run_command = _console_window_stub("old line one\nold line two")
    _blj2 = c.get("/api/console/%d" % gs_id).get_json() or {}
    check("console timestamps: (setup) the game-log window came back non-empty",
          len(_blj2.get("lines") or []) >= 2,
          "lines=%s — the check below would pass vacuously" % (_blj2.get("lines"),))
    check("console timestamps: an UNSTAMPED history line carries no invented time",
          all(r.get("t") is None for r in (_blj2.get("lines") or [])),
          "a line was dated to the moment the panel read it: %s" % (_blj2.get("lines"),))
    # The control for the readable=False check above: a read that DID run still says so, or
    # that gate would pass on a route that simply reported every console unreadable.
    check("console read: ...and a console that WAS read says so too",
          _blj2.get("readable") is True, "readable=%r" % (_blj2.get("readable"),))
    check("console backlog: the colour survives the round trip to the page",
          any("\x1b[32m" in (r.get("line") or "") for r in _bl_rows),
          "panel_lines=%s" % _bl_rows)
    # Bounded — this must never quietly become a second copy of the log.
    for _i in range(_CONSOLE_BACKLOG_MAX + 120):
        _console_push(app, gs_id, "line %d" % _i)
    check("console backlog: it is capped, and keeps the NEWEST lines",
          len(_cb[gs_id]) == _CONSOLE_BACKLOG_MAX
          and _cb[gs_id][-1]["line"] == "line %d" % (_CONSOLE_BACKLOG_MAX + 119),
          "len=%d last=%r" % (len(_cb[gs_id]), _cb[gs_id][-1]))

    # End to end: what the DRAIN sends for a LinuxGSM-coloured line. The words must be intact
    # and the colour must be canonical — the browser splits on ESC[<codes>m and nothing else,
    # so a stray erase-line or OSC reaching it renders as visible junk.
    _cb.clear()
    _col_file = {"text": "\x1b[0;32m[  OK  ]\x1b[0m Starting\x1b[K\n\x1b]0;steamcmd\x07done\n"}

    def _col_rc(server, command, timeout=30, sudo=None):
        if "stat -c%s" in command and ".panel-" in command:
            t = _col_file["text"]
            _m = _lat_re.search(r"tail -c \+(\d+)", command)
            _pos = (int(_m.group(1)) - 1) if _m else 0
            return ("%d\n%s" % (len(t), t[_pos:] if len(t) > _pos else "")).strip(), "", 0
        return ("0", "", 0)

    _sm_core.run_command = _col_rc
    with app.app_context():
        _col_remote = db.session.get(GameServer, gs_id).remote
        _begin_action_tail(app, gs_id, "update", "/home/x/.panel-update.log", "csgoserver")
        _drain_action_output(app, _col_remote, gs_id)
        _ao.pop(gs_id, None)
    _col_sent = "\n".join(r["line"] for r in _cb.get(gs_id, []))
    check("console colour: LinuxGSM's [  OK  ] reaches the page still green",
          "\x1b[32m[  OK  ]\x1b[0m" in _col_sent, "sent %r" % _col_sent)
    check("console colour: ...and the erase-line and window-title escapes do NOT",
          "\x1b[K" not in _col_sent and "\x1b]" not in _col_sent
          and "steamcmd" not in _col_sent, "sent %r" % _col_sent)
    # Everything that is not colour must be gone: the browser builds text nodes from what is
    # between the SGR sequences, so any other control byte would be rendered literally.
    _col_bare = _lat_re.sub(r"\x1b\[[0-9;]*m", "", _col_sent)
    check("console colour: no control byte but the colour itself survives the drain",
          not any(ord(ch) < 32 and ch != "\n" for ch in _col_bare), "bare %r" % _col_bare)
finally:
    _sm_core.run_command = _bl_saved
    _cb.clear()
    _ao.clear()

# ── Every stored timestamp on a page is rendered in the VIEWER's clock ──────────────────
# The panel stores naive UTC everywhere (panel/core/clock.py) and localises on the CLIENT, so
# two admins in different countries each read their own time off the same row. That only holds
# for values emitted through the |datetime filter — three templates formatted a datetime with
# .strftime() instead and showed raw UTC with nothing saying so, which reads as a wrong local
# time rather than as a UTC one. Asserted as "no template renders a stored datetime without
# going through the filter", so the next one added is caught rather than the three being
# spot-checked forever.
import glob as _tz_glob
import re as _tz_re  # pylint: disable=reimported
_tz_bad = []
for _tz_path in sorted(_tz_glob.glob(os.path.join(_repo_root, "templates", "*.html"))):
    _tz_src = open(_tz_path, encoding="utf-8").read()
    _tz_src = _tz_re.sub(r"\{#.*?#\}", "", _tz_src, flags=_tz_re.S)   # Jinja comments
    for _tz_m in _tz_re.finditer(r"\{\{(.*?)\}\}", _tz_src, _tz_re.S):
        _tz_expr = _tz_m.group(1)
        if ".strftime(" in _tz_expr and "|datetime" not in _tz_expr:
            _tz_bad.append("%s: {{%s}}" % (os.path.basename(_tz_path), _tz_expr.strip()[:70]))
check("time: no template formats a stored timestamp itself (it must go through |datetime)",
      not _tz_bad, "raw strftime in a template shows UTC as if it were local: %s" % _tz_bad[:3])
# Vacuity guard: the scan must actually be finding the filter, or the check above passes on a
# repo where nothing renders a timestamp at all.
_tz_filtered = sum(1 for _p in _tz_glob.glob(os.path.join(_repo_root, "templates", "*.html"))
                   if "|datetime" in open(_p, encoding="utf-8").read())
check("time: (setup) templates really do use the |datetime filter",
      _tz_filtered >= 4, "only %d templates use it — the gate above proves little" % _tz_filtered)
# And the filter has to emit what the client-side localiser looks for, or it silently shows UTC.
_tz_html = c.get("/logs").get_data(as_text=True)
check("time: the filter emits a localtime span the browser can rewrite",
      'class="localtime" data-utc="' in _tz_html,
      "no .localtime[data-utc] in /logs — localizeTimes() has nothing to act on")
check("time: ...and the value it carries is UTC-anchored, so the browser parses it as UTC",
      _tz_re.search(r'data-utc="\d{4}-\d{2}-\d{2}T[\d:]+Z"', _tz_html) is not None,
      "a naive ISO string with no Z is parsed as LOCAL time and is silently wrong by the offset")


# ── A poll delta is a line the panel WATCHED ARRIVE, so it gets a time ───────────────────
# The first cut stamped only socket pushes. /api/console's window was left unstamped whole —
# but only its PRIMING pass is history; everything after is new output the panel just read,
# accurate to the poll interval. Two consequences, and the second is why this was reported as
# "I still don't see the timestamps in the console":
#   * an install whose websocket cannot connect (a proxy that will not upgrade) falls back to
#     this poll for everything, so NO line ever got a time at all;
#   * on a quiet server every line on screen is the priming window, so the column is empty and
#     the feature looks broken rather than correct.
_pd_saved = _sm_core.run_command
try:
    _sm_core.run_command = _console_window_stub("first\nsecond")
    _pdj = c.get("/api/console/%d" % gs_id).get_json() or {}
    check("console timestamps: the window carries the panel's clock for the browser to stamp "
          "its new lines with",
          isinstance(_pdj.get("now"), (int, float)) and _pdj["now"] > 1_700_000_000,
          "now=%r" % _pdj.get("now"))
    # Still not dated per line: an unstamped window is history until the browser knows which of
    # it is new, and dating the whole thing server-side is the mistake this guards against.
    # ...over lines that exist: an empty window makes all(...) True and the claim empty.
    _pd_lines = _pdj.get("lines") or []
    check("console timestamps: the unstamped window came back with lines in it",
          len(_pd_lines) >= 1, "no lines — the next check would pass vacuously")
    check("console timestamps: ...but an unstamped window stays undated, as history",
          _pd_lines and all(r.get("t") is None for r in _pd_lines),
          "lines=%s" % (_pd_lines,))

    # ── The window keeps its edge whitespace, because the page matches it EXACTLY ────────
    # run_command strips its output, so an unframed `tail` lost the window's LAST line's
    # trailing space and its FIRST line's indentation. The browser de-duplicates this window
    # against the lines the poller pushed — which are framed, and were not stripped — so
    # after Minecraft's "…players online: " the page found no overlap and appended the whole
    # window again under the reply, every poll. Reported as "the live console stops
    # responding till I load more of the old log"; measured on the test VPS as +29 and +33
    # repeated lines after each `list`.
    _sm_core.run_command = _console_window_stub(
        "    at lua/includes/init.lua:12\n[03:30:35] There are 0 of a max of 20 players online: ")
    _ws_lines = [r.get("line") for r in (c.get("/api/console/%d" % gs_id).get_json() or {})
                 .get("lines") or []]
    check("console window: the last line keeps its trailing whitespace",
          _ws_lines[-1:] == ["[03:30:35] There are 0 of a max of 20 players online: "],
          "last line %r — the page's exact-match stitching cannot find it" % (_ws_lines[-1:],))
    check("console window: ...and the first line keeps its indentation",
          _ws_lines[:1] == ["    at lua/includes/init.lua:12"], "first line %r" % (_ws_lines[:1],))
    check("console window: ...and the file's final newline is not an extra empty line",
          len(_ws_lines) == 2, "lines=%r" % (_ws_lines,))
    # tail's OWN status must survive the frame. Run the route's actual command through a
    # real bash — a stub cannot tell `…; printf E` from `…; printf E; exit $r`, and without
    # the exit a MISSING log (LinuxGSM's start is mv-then-touch) reads as "readable, empty",
    # which Load older answers by wiping the console.
    import subprocess as _rs_sp
    import tempfile as _rs_tmp
    with app.app_context():
        _rs_path = db.session.get(GameServer, gs_id).console_log
    _rs_dir = _rs_tmp.mkdtemp()
    _rs_target = [os.path.join(_rs_dir, "console.log")]
    _rs_saved = _sm_core.read_as_game_user

    def _rs_read(_server, _user, sh, timeout=30, selfname=None):
        r = _rs_sp.run(["bash", "-c", sh.replace(_rs_path, _rs_target[0])],
                       capture_output=True, text=True, timeout=10)
        return r.stdout.strip(), r.stderr.strip(), r.returncode   # .strip(): the transport
    try:
        _sm_core.read_as_game_user = _rs_read
        with open(_rs_target[0], "w") as _rs_fh:
            _rs_fh.write("first line\nThere are 0 of a max of 20 players online: \n")
        _rs_ok = c.get("/api/console/%d" % gs_id).get_json() or {}
        check("console window: (real shell) a present log is read, edge whitespace intact",
              _rs_ok.get("readable") is True
              and [r.get("line") for r in _rs_ok.get("lines") or []]
              == ["first line", "There are 0 of a max of 20 players online: "],
              "readable=%r lines=%r" % (_rs_ok.get("readable"), _rs_ok.get("lines")))
        _rs_target[0] = os.path.join(_rs_dir, "does-not-exist.log")
        _rs_missing = c.get("/api/console/%d" % gs_id).get_json() or {}
        check("console window: (real shell) a MISSING log is not reported as readable",
              _rs_missing.get("readable") is False,
              "readable=%r — Load older would wipe the console for a log that is not there"
              % (_rs_missing.get("readable"),))
    finally:
        _sm_core.read_as_game_user = _rs_saved
        import shutil as _rs_sh
        _rs_sh.rmtree(_rs_dir, ignore_errors=True)
    # The frame is also the positive token that the read ran: output without it (a transport
    # that returned something else entirely) is not a window of the log.
    _sm_core.run_command = lambda *a, **k: ("sudo: a password is required", "", 0)
    _ws_bad = c.get("/api/console/%d" % gs_id).get_json() or {}
    check("console window: an unframed answer is reported unreadable, not shown as the log",
          _ws_bad.get("readable") is False and _ws_bad.get("lines") == [],
          "readable=%r lines=%r" % (_ws_bad.get("readable"), _ws_bad.get("lines")))
finally:
    _sm_core.run_command = _pd_saved


# ── A schedule is entered in YOUR clock and written in the HOST's ────────────────────────
# cron fires on the host's clock. set_daily_restart wrote a literal `0 5 * * *`, the panel's
# own bootstrap sets new hosts to UTC, no host's timezone was stored anywhere, and the UI
# showed no time at all — so "daily restart" on a US Central operator's server fired at 23:00
# local, in peak hours, with nothing on screen to notice it by.
from panel.core import clock as _tzc
_tz_saved = (_sm_core.run_command, _sm_core._rewrite_crontab)
_tz_lines = []
try:
    _sm_core._rewrite_crontab = lambda s, u, g, add, extra_pre="": (_tz_lines.extend(add),
                                                                    (True, "ok"))[1]
    # A host on UTC, which is what this panel's own bootstrap gives a new VPS.
    with app.app_context():
        db.session.get(RemoteServer, remote_id).timezone = "Etc/UTC"
        db.session.commit()
    # 05:00 America/Chicago is 10:00 or 11:00 UTC depending on the season, so compute the
    # expectation the same way rather than hardcoding one of them — a test that pins 11:00
    # goes red every spring for a reason that has nothing to do with the code.
    _tz_exp_h, _tz_exp_m = _tzc.convert_wall_time(5, 0, "America/Chicago", "Etc/UTC")
    _tz_lines.clear()
    _tzj = c.post("/api/server/%d/daily-restart" % gs_id,
                  json={"enabled": True, "time": "05:00", "tz": "America/Chicago"}).get_json() or {}
    check("schedule tz: the crontab line is written in the HOST's clock, not the viewer's",
          any(_l.startswith("%d %d * * *" % (_tz_exp_m, _tz_exp_h)) for _l in _tz_lines),
          "wrote %s, wanted the daily line at %02d:%02d UTC" % (_tz_lines, _tz_exp_h, _tz_exp_m))
    check("schedule tz: ...and the response says BOTH times, so the page can show which is which",
          _tzj.get("host_time") == "%02d:%02d" % (_tz_exp_h, _tz_exp_m)
          and _tzj.get("local_time") == "05:00" and _tzj.get("host_tz") == "Etc/UTC",
          "got %s" % _tzj)
    with app.app_context():
        check("schedule tz: the stored time is the host's, which is what the crontab says",
              db.session.get(GameServer, gs_id).daily_restart_at
              == "%02d:%02d" % (_tz_exp_h, _tz_exp_m),
              "stored %r" % db.session.get(GameServer, gs_id).daily_restart_at)
    # Flicking the switch sends NO time. That must keep the schedule where it is — a toggle
    # that silently reset it to a default would move a restart into peak hours.
    _tz_lines.clear()
    c.post("/api/server/%d/daily-restart" % gs_id, json={"enabled": False})
    _tz_lines.clear()
    c.post("/api/server/%d/daily-restart" % gs_id, json={"enabled": True})
    check("schedule tz: toggling off and on again does not move the time",
          any(_l.startswith("%d %d * * *" % (_tz_exp_m, _tz_exp_h)) for _l in _tz_lines),
          "wrote %s" % _tz_lines)
    # An UNREADABLE host must leave the time exactly where the operator put it. Converting
    # against a guessed zone would silently shift every schedule on that host.
    with app.app_context():
        db.session.get(RemoteServer, remote_id).timezone = ""
        db.session.commit()
    _sm_core.run_command = lambda *a, **k: ("", "", 1)      # timezone unreadable
    _tz_lines.clear()
    _tzj2 = c.post("/api/server/%d/daily-restart" % gs_id,
                   json={"enabled": True, "time": "07:30", "tz": "America/Chicago"}).get_json() or {}
    check("schedule tz: an unreadable host timezone leaves the time alone, it does not guess",
          any(_l.startswith("30 7 * * *") for _l in _tz_lines) and _tzj2.get("host_tz") == "",
          "wrote %s, said %s" % (_tz_lines, _tzj2))
    # The conversion itself, including the direction that matters and the no-ops.
    check("schedule tz: (unit) a wall time converts between zones",
          _tzc.convert_wall_time(5, 0, "America/Chicago", "Etc/UTC")[0] in (10, 11),
          "got %s" % (_tzc.convert_wall_time(5, 0, "America/Chicago", "Etc/UTC"),))
    check("schedule tz: (unit) the same zone, or an unknown one, is a no-op",
          _tzc.convert_wall_time(5, 0, "Etc/UTC", "Etc/UTC") == (5, 0)
          and _tzc.convert_wall_time(5, 0, "Nope/Nope", "Etc/UTC") == (5, 0)
          and _tzc.convert_wall_time(5, 0, "", "Etc/UTC") == (5, 0))
    # The zone name arrives from the browser AND from a remote host's timedatectl, and ends
    # up indexing the zone database, in a stored column and on the page — so what matters is
    # that a non-zone never survives, whichever layer refuses it (this module's shape check,
    # or zoneinfo's own rejection of absolute paths and `..`).
    check("schedule tz: a zone name that is not one is refused, path traversal included",
          _tzc.valid_timezone("../../etc/passwd") == ""
          and _tzc.valid_timezone("Etc/../../x") == ""
          and _tzc.valid_timezone("A" * 80) == ""
          and _tzc.valid_timezone("America/Chicago") == "America/Chicago")
    check("schedule tz: (unit) a malformed time falls back rather than raising",
          _tzc.parse_hhmm("25:00") == (5, 0) and _tzc.parse_hhmm("") == (5, 0)
          and _tzc.parse_hhmm("7:05") == (7, 5))
finally:
    (_sm_core.run_command, _sm_core._rewrite_crontab) = _tz_saved
    with app.app_context():
        db.session.get(RemoteServer, remote_id).timezone = ""
        db.session.commit()


# ── LinuxGSM's own per-line stamp gives HISTORY a real time ─────────────────────────────
# The panel tails the console log, so on its own it can only date what it watched arrive — an
# idle server's whole history is blank, which is what "can you make it always keep track of
# time" was asking about. LinuxGSM can stamp the log AT WRITE TIME (`logtimestamp="on"` pipes
# the tmux capture through `gawk strftime`, command_start.sh), and that stamp survives in the
# file. It is written in the HOST's local time with no offset, which is why this needs
# RemoteServer.timezone — the whole reason that column exists.
from panel.core import terminal as _lt_term
from panel.routes._shared import _console_rows as _lt_rows
_lt_saved = _sm_core.run_command
try:
    check("log stamps: LinuxGSM's shape is parsed off the line, and stripped from the text",
          _lt_term.split_log_timestamp("[2026-09-18 05:09:57] ] Player connected")
          == ("2026-09-18 05:09:57", "] Player connected"),
          "got %s" % (_lt_term.split_log_timestamp("[2026-09-18 05:09:57] ] Player connected"),))
    # A game printing something bracket-shaped of its own must not be mistaken for a stamp and
    # have its first word eaten.
    check("log stamps: a bracketed line that is NOT a timestamp is left completely alone",
          _lt_term.split_log_timestamp("[PH:X Integrity Check] No errors found.")
          == (None, "[PH:X Integrity Check] No errors found."),
          "got %s" % (_lt_term.split_log_timestamp("[PH:X Integrity Check] No errors."),))
    # The conversion: written in the host's clock, stored as an epoch, rendered in the
    # viewer's. 05:09:57 in Tokyo is NOT 05:09:57 anywhere else.
    _lt_rowset = _lt_rows(["[2026-09-18 05:09:57] hello", "no stamp here"], "Asia/Tokyo")
    _lt_want = _tzc.host_stamp_to_epoch("2026-09-18 05:09:57", "Asia/Tokyo")
    check("log stamps: the stamp becomes a UTC epoch read in the HOST's timezone",
          _lt_rowset[0]["t"] == _lt_want and _lt_want is not None,
          "got %s, wanted %s" % (_lt_rowset[0]["t"], _lt_want))
    check("log stamps: ...and it is a DIFFERENT instant than the same wall time elsewhere",
          _tzc.host_stamp_to_epoch("2026-09-18 05:09:57", "Asia/Tokyo")
          != _tzc.host_stamp_to_epoch("2026-09-18 05:09:57", "America/Chicago"),
          "two zones produced the same epoch — the host timezone is being ignored")
    check("log stamps: an unstamped line beside a stamped one still carries no time",
          _lt_rowset[1]["t"] is None and _lt_rowset[1]["line"] == "no stamp here",
          "got %s" % (_lt_rowset[1],))
    # A host whose timezone is unknown must NOT have its stamps read against a guess: a line
    # dated nine hours wrong is worse than one with no date.
    check("log stamps: an unknown host timezone yields no time rather than a guessed one",
          _lt_rows(["[2026-09-18 05:09:57] hello"], "")[0]["t"] is None,
          "a stamp was converted against a guessed zone")

    # End to end through the endpoint the console actually calls.
    with app.app_context():
        db.session.get(RemoteServer, remote_id).timezone = "Asia/Tokyo"
        db.session.commit()
    _sm_core.run_command = _console_window_stub("[2026-09-18 05:09:57] stamped line\nplain line")
    _ltj = c.get("/api/console/%d" % gs_id).get_json() or {}
    _lt_got = _ltj.get("lines") or []
    check("log stamps: the console window carries the real time for a stamped line",
          len(_lt_got) == 2 and _lt_got[0]["t"] == _lt_want
          and _lt_got[0]["line"] == "stamped line",
          "got %s" % (_lt_got,))
    check("log stamps: ...and none for the unstamped one beside it",
          len(_lt_got) == 2 and _lt_got[1]["t"] is None, "got %s" % (_lt_got,))
    check("log stamps: the window says whether the log is stamped at all",
          _ltj.get("log_timestamps") is True, "log_timestamps=%r" % _ltj.get("log_timestamps"))

    # Turning it on is a LinuxGSM CONFIG edit, so it needs the config permission and it only
    # takes effect on the next start — both reported rather than assumed away.
    _lt_writes = []
    from panel.routes import server_files as _lt_sf  # pylint: disable=reimported
    _lt_wr = _lt_sf.lgsm_write_config
    try:
        _lt_sf.lgsm_write_config = lambda s, u, n, upd: (_lt_writes.append(upd), (True, "ok"))[1]
        _ltp2 = c.post("/api/server/%d/log-timestamps" % gs_id,
                       json={"enabled": False}).get_json() or {}
        check("log stamps: turning it OFF writes 'off', not a missing key",
              _lt_writes and _lt_writes[0].get("logtimestamp") == "off"
              and _ltp2.get("enabled") is False, "wrote %s got %s" % (_lt_writes, _ltp2))
        check("log stamps: ...and says it needs a restart, because pipe-pane is set up at start",
              _ltp2.get("success") is True and _ltp2.get("needs_restart") is True,
              "got %s" % _ltp2)
        # The page has no ON control; the endpoint must not have one either. Turning it on
        # routes the console through gawk, which block-buffers to the file — a console that
        # looks frozen until 4KB accumulate.
        _lt_writes.clear()
        _ltp_on = c.post("/api/server/%d/log-timestamps" % gs_id, json={"enabled": True})
        check("log stamps: the endpoint REFUSES to turn stamping on",
              _ltp_on.status_code == 400 and not _lt_writes,
              "status %s, wrote %s — one request still freezes every viewer's console"
              % (_ltp_on.status_code, _lt_writes))
    finally:
        _lt_sf.lgsm_write_config = _lt_wr
finally:
    _sm_core.run_command = _lt_saved
    with app.app_context():
        db.session.get(RemoteServer, remote_id).timezone = ""
        db.session.commit()


# ── A burst bigger than the read cap must not lose output, or cut a line in half ─────────
# The poller reads at most 64KB per tick and then set last_pos to the file's FULL size, so
# everything past the cap was silently discarded — and the 64KB boundary itself landed
# mid-line, which reached the screen as a bare "[20" where a timestamp had been sliced. A
# server writing more than 64KB between two 2-second polls is not hypothetical: it is every
# GMod start, loading hundreds of Lua modules, which is exactly when someone is watching.
# Reported as "as the server loads it stops".
_bs_log = "".join("[2026-09-18 06:22:08] MODULE: cc_module_%05d.lua\n" % i for i in range(3000))
check("console burst: (setup) the fixture is bigger than one read", len(_bs_log) > 65536 * 2,
      "only %d bytes — the cap would never be hit" % len(_bs_log))

# Drive the REAL reassembly, not a copy of it: _console_whole_lines is what the poller calls.
# The first version of this test walked its own copy of the arithmetic and passed cheerfully
# with the carry deleted from the production code it was meant to guard.
from panel.routes.server_files import _console_whole_lines as _bs_whole_lines
from panel.core.panel_state import _console_partial as _bs_partial_state
_bs_partial_state.pop(-99, None)
_bs_pos, _bs_seen = 0, []
for _ in range(12):
    if _bs_pos >= len(_bs_log):
        break
    _bs_diff = min(len(_bs_log) - _bs_pos, 65536)
    # exactly what the shell returns: the byte range inside its B…E frame
    _bs_out = _bs_whole_lines(-99, "B" + _bs_log[_bs_pos:_bs_pos + _bs_diff] + "E")
    if _bs_out:
        _bs_seen.extend(_bs_out.split("\n"))
    _bs_pos = _bs_pos + _bs_diff          # the fix: advance by what was READ
check("console burst: nothing is dropped — every line of the burst arrives",
      len(_bs_seen) == 3000, "saw %d of 3000 lines" % len(_bs_seen))
check("console burst: ...and not one of them is a fragment",
      all(l.startswith("[2026-09-18 06:22:08] MODULE: ") and l.endswith(".lua")
          for l in _bs_seen),
      "a line was cut at a read boundary: %s"
      % [l for l in _bs_seen if not l.endswith(".lua")][:2])
check("console burst: ...in order, with no duplicates",
      _bs_seen == [l for l in _bs_log.split("\n") if l],
      "the reassembled stream does not match the file")
# The source of the bug, pinned directly: advancing to the file's size instead of to what was
# read is what threw the rest away.
_bs_src = open(os.path.join(_repo_root, "panel", "routes", "server_files.py"),
               encoding="utf-8").read()
check("console burst: a rotated log drops the half-line held from the old file",
      "_console_partial.pop(server_id, None)" in _bs_src,
      "the fragment from the previous log survives the rotation and is glued to the new one")

# ── The chunk is framed at BOTH ends, because run_command strips both ────────────────────
# run_command returns `.strip()`ed output on every transport (_core.py: `out.strip()`,
# `r.stdout.strip()`, `(out or "").strip()`), and strip() is not rstrip(). Only the trailing
# 'E' sentinel existed, which covered exactly half the problem. When a byte-range chunk BEGAN
# with the newline that terminated the previous chunk's last line, that newline was deleted in
# transit and the held fragment was concatenated straight onto the next line's text: two real
# log lines reached the console as one, with a second timestamp welded into the middle of it —
# which also defeats _console_rows' stamp parsing for that line.
_bs_partial_state.pop(-98, None)
_lb_seen = []
for _lb_chunk in ("[2026-09-18 06:22:08] MODULE: cc_foo.lua",      # cut on a line boundary…
                  "\n[2026-09-18 06:22:08] MODULE: cc_bar.lua\n"):  # …so the next byte is \n
    # .strip() is what the transport does to the framed chunk before the route ever sees it
    _lb_out = _bs_whole_lines(-98, ("B" + _lb_chunk + "E").strip())
    if _lb_out:
        _lb_seen.extend(_lb_out.split("\n"))
check("console chunk: a chunk that STARTS with a newline is not glued to the held fragment",
      _lb_seen == ["[2026-09-18 06:22:08] MODULE: cc_foo.lua",
                   "[2026-09-18 06:22:08] MODULE: cc_bar.lua"],
      "reassembled as %r — a line that never existed in the log" % (_lb_seen,))
_bs_partial_state.pop(-98, None)
check("console chunk: ...and the poller frames the read at both ends to make that true",
      "printf B; {" in _bs_src and "}; printf E" in _bs_src,
      "the command sentinels only one end, so the transport's leading strip still bites")

# ── A read that never RAN must not advance the offset ────────────────────────────────────
# tailscale (_run_via_ssh_cli) and local do NOT raise: a 64KB `tail | head` that exceeds the
# 5s timeout returns ("", "SSH command timed out", -1), while the 20-byte stat in the same tick
# succeeded. "" was indistinguishable from "the chunk held no complete line", so the poller
# advanced last_pos by `diff` bytes the host never sent — gone permanently, because last_pos
# only moves forward and the browser only ever sees what the poller emitted. The frame is the
# positive token that proves the read ran; its ABSENCE must not read as success.
_bs_partial_state.pop(-97, None)
_bs_partial_state[-97] = "[2026-09-18 06:22:08] MODULE: cc_hal"   # half a line, held
_ur_out = _bs_whole_lines(-97, "")
check("console chunk: a read that did not run answers None, not an empty chunk",
      _ur_out is None,
      "answered %r — the caller cannot tell it from a log that wrote nothing" % (_ur_out,))
check("console chunk: ...and it does not consume the fragment held from the last read",
      _bs_partial_state.get(-97) == "[2026-09-18 06:22:08] MODULE: cc_hal",
      "held fragment is now %r — the next tick cannot re-read the range"
      % (_bs_partial_state.get(-97),))
# The control: a framed chunk that is EMPTY is a reading — the log wrote nothing this tick —
# and must still come back as "", not None, or the poller would stall on an idle server.
check("console chunk: (control) a framed empty chunk is a reading, not a failure",
      _bs_whole_lines(-97, "BE") == "",
      "an idle server's empty read now looks like a failed one, and the offset never advances")
_bs_partial_state.pop(-97, None)

# Driven through the poller's own loop shape, because the damage is in the offset arithmetic
# rather than in one call: one tick's chunk read fails the way tailscale fails, and every byte
# of the burst must still arrive.
_bs_partial_state.pop(-96, None)
_fp_log = "".join("[2026-09-18 06:22:08] MODULE: fp_%05d.lua\n" % i for i in range(3000))
check("console poller: (setup) the fixture spans more than one capped read",
      len(_fp_log) > 65536, "only %d bytes" % len(_fp_log))
_fp_pos, _fp_seen, _fp_tick = 0, [], 0
while _fp_pos < len(_fp_log) and _fp_tick < 20:
    _fp_tick += 1
    _fp_diff = min(len(_fp_log) - _fp_pos, 65536)
    _fp_raw = ("" if _fp_tick == 2                     # the timed-out read: no frame, rc=-1
               else "B" + _fp_log[_fp_pos:_fp_pos + _fp_diff] + "E")
    _fp_out = _bs_whole_lines(-96, _fp_raw)
    if _fp_out is None:
        continue                                       # the fix: do NOT advance last_pos
    if _fp_out:
        _fp_seen.extend(_fp_out.split("\n"))
    _fp_pos += _fp_diff
_bs_partial_state.pop(-96, None)
check("console poller: a chunk read that never ran does not advance the offset past it",
      _fp_seen == [_l for _l in _fp_log.split("\n") if _l],
      "saw %d of %d lines — a window of console output was skipped and can never be "
      "recovered" % (len(_fp_seen), 3000))
check("console poller: ...and the poller refuses the advance on that answer",
      "if out is None:" in _bs_src
      and "out = _console_whole_lines(server_id, framed) if rc == 0 else None" in _bs_src,
      "the offset still moves on a read whose result was never proven to have arrived")

# ── The REAL tick, against a fake log that rotates the way LinuxGSM rotates it ───────────
# Everything above drives _console_whole_lines; the offset arithmetic around it lived in the
# poller's closure, so it could only be checked by reading its source — and a source check
# cannot tell a rotation the poller handles from one it misses. It missed one. LinuxGSM's
# start is `mv consolelog <dated>; touch consolelog`, and rotation was detected only by the
# file SHRINKING. On the test VPS a Minecraft start wrote 4.5KB in under two seconds, outgrew
# the old log's 4528-byte offset before the next tick, and the poller read the NEW log from
# the OLD offset: the boot output was never shown and the first push began
# 'l:joml:1.10.9) to libraries/…'. _console_tick is the extracted body; this drives it.
import re as _ct_re  # pylint: disable=reimported
import types as _ct_types
from panel.routes import server_files as _ct_sf  # pylint: disable=reimported
from panel.core.panel_state import _console_offsets as _ct_offsets


class _CtLog:
    """A console log on a fake host, answering exactly the two reads _console_tick makes."""
    def __init__(self):
        self.ino, self.data, self.exists, self.fail_chunk = 5000, "", True, False

    def rotate(self, text=""):             # mv consolelog <dated>; touch consolelog
        self.ino, self.data = self.ino + 1, text

    def read(self, _server, _user, sh, timeout=30, selfname=None):
        if sh.startswith("stat -c '%i %s'"):
            return ("%d %d" % (self.ino, len(self.data)) if self.exists else "MISSING"), "", 0
        # The tick's one command after first sight (server_files._console_poll_cmd): the stat,
        # the start the host picks from the inode and offset it is handed, the framed bytes.
        m = _ct_re.match(r"L=\S+; S=\$\(stat -c '%i %s' \"\$L\" 2>/dev/null\) \|\| "
                         r"\{ echo MISSING; exit 0; \}; set -- \$S; "
                         r"if \[ \"\$1\" = (\d+) \] && \[ \"\$2\" -ge (\d+) \]; then P=\2; "
                         r"else P=0; fi; D=\$\(\(\$2 - P\)\); if \[ \"\$D\" -gt (\d+) \]; "
                         r"then D=\3; fi; ", sh)
        if not m:
            return "", "unexpected command %r" % sh, 1
        if not self.exists:
            return "MISSING", "", 0
        if self.fail_chunk:
            self.fail_chunk = False
            return "", "SSH command timed out", -1      # tailscale/local: no raise, no frame
        size = len(self.data)
        a = int(m.group(2)) if (int(m.group(1)) == self.ino and size >= int(m.group(2))) else 0
        n = min(size - a, int(m.group(3)))
        # .strip(): what every transport does to the output before the caller sees it
        return ("%d %d %d %d" % (self.ino, size, a, n)
                + ("\nB" + self.data[a:a + n] + "E" if n else "")).strip(), "", 0


class _CtSio:
    def __init__(self):
        self.lines = []

    def emit(self, event, payload, room=None, **_k):
        if event == "console_output":
            self.lines.extend(r["line"] for r in payload.get("rows") or [])


_ct_log, _ct_sio = _CtLog(), _CtSio()
_ct_gs = _ct_types.SimpleNamespace(console_log="/home/mcserver/log/console/mc-console.log",
                                   remote=object(), short_name="mcserver", lgsm_name="mcserver")
# On _core, the defining module: the package resolves names through __getattr__, and a stub
# set on the package itself would shadow that (the unit suite's stub-seam gate says so).
_ct_saved = (_sm_core.read_as_game_user, _ct_sf._host_timezone_cached)
_CT = -95


def _ct_tick():
    _ct_sf._console_tick(app, _ct_sio, _ct_gs, _CT)


try:
    _sm_core.read_as_game_user = _ct_log.read
    _ct_sf._host_timezone_cached = lambda *_a, **_k: ""
    _ct_offsets.pop(_CT, None)
    _bs_partial_state.pop(_CT, None)
    _ct_log.data = "".join("[03:30:%02d] old line %d\n" % (i, i) for i in range(40))
    _ct_tick()
    check("console tick: first sight reads nothing — history is /api/console's to show",
          _ct_sio.lines == [] and _ct_offsets.get(_CT, {}).get("pos") == len(_ct_log.data),
          "pushed %d lines / offset %r" % (len(_ct_sio.lines), _ct_offsets.get(_CT)))
    _ct_log.data += "list\n[03:30:35] There are 0 of a max of 20 players online: \n"
    _ct_tick()
    check("console tick: (control) new output after first sight is pushed, whitespace intact",
          _ct_sio.lines == ["list", "[03:30:35] There are 0 of a max of 20 players online: "],
          "pushed %r" % (_ct_sio.lines,))

    # THE REPORTED CASE: a start rotates the log and the new one is already LONGER than the
    # old offset by the time the poller next looks.
    _ct_sio.lines = []
    _ct_boot = ["Unpacking io/netty/netty-codec/4.2.7/netty-codec-4.2.7.jar (libraries:io.netty:"
                "netty-codec:4.2.7) to libraries/io/netty/netty-codec/4.2.7/netty-codec.jar %03d"
                % i for i in range(60)] + ["Starting net.minecraft.server.Main"]
    _ct_log.rotate("".join(l + "\n" for l in _ct_boot))
    check("console tick: (setup) the new log outgrew the old offset before the tick",
          len(_ct_log.data) > _ct_offsets[_CT]["pos"],
          "new %d <= old %d — the size check alone would already catch it"
          % (len(_ct_log.data), _ct_offsets[_CT]["pos"]))
    _ct_tick()
    check("console tick: a rotated log is read from its FIRST byte, not from the old offset",
          _ct_sio.lines[:1] == _ct_boot[:1],
          "first pushed line %r — the boot output before it was skipped, and it began "
          "mid-line" % (_ct_sio.lines[:1],))
    check("console tick: ...and every line of the new log arrives, in order, whole",
          _ct_sio.lines == _ct_boot, "pushed %d of %d lines" % (len(_ct_sio.lines),
                                                              len(_ct_boot)))

    # A rotation that SHRINKS the file (the older, size-only detection) must still work, and
    # read from byte 0 rather than skipping the new log's first chunk as "first sight".
    _ct_sio.lines = []
    _ct_log.rotate("[03:40:00] Starting minecraft server version 26.3\n")
    _ct_tick()
    check("console tick: a smaller rotated log is read from byte 0, not skipped",
          _ct_sio.lines == ["[03:40:00] Starting minecraft server version 26.3"],
          "pushed %r" % (_ct_sio.lines,))

    # Between LinuxGSM's mv and its touch there is no file at all. That is not an empty log
    # and not a rotation, and it must not disturb the offset.
    _ct_before = dict(_ct_offsets[_CT])
    _ct_log.exists = False
    _ct_tick()
    _ct_log.exists = True
    check("console tick: a log that is briefly MISSING changes nothing",
          _ct_offsets[_CT] == _ct_before, "offset %r -> %r" % (_ct_before, _ct_offsets[_CT]))

    # A chunk read that does not run (the non-raising transports) must not advance: the next
    # tick re-reads the range. This is the case the loop-shaped check above simulates; here
    # it goes through the real function.
    _ct_sio.lines = []
    _ct_log.data += "[03:40:05] Done (4.2s)! For help, type \"help\"\n"
    _ct_log.fail_chunk = True
    _ct_tick()
    _ct_mid = list(_ct_sio.lines)
    _ct_tick()
    check("console tick: a chunk read that never ran is retried, not skipped",
          _ct_mid == [] and _ct_sio.lines == ['[03:40:05] Done (4.2s)! For help, type "help"'],
          "after the failed read %r, after the retry %r" % (_ct_mid, _ct_sio.lines))

    # A burst over the per-tick cap drains over several ticks with nothing lost or cut.
    _ct_sio.lines = []
    # Unstamped: a LinuxGSM "[YYYY-MM-DD HH:MM:SS] " prefix is parsed off into the row's `t`,
    # so a stamped fixture would compare unequal for a reason that has nothing to do with this.
    _ct_burst = ["MODULE: ct_%05d.lua loaded" % i for i in range(3000)]
    _ct_log.data += "".join(l + "\n" for l in _ct_burst)
    for _ in range(12):
        _ct_tick()
    check("console tick: a burst bigger than one read arrives complete, in order, unsplit",
          _ct_sio.lines == _ct_burst,
          "pushed %d of 3000; first bad %r" % (len(_ct_sio.lines),
                                              [l for l in _ct_sio.lines if not l.endswith(" loaded")][:1]))

    # One absurd colour code must not wedge the console. int() of more than 4300 digits
    # RAISES in CPython, the renderer runs on every chunk, and a tick that raises never
    # advances — so the same chunk was re-read, and re-raised, every two seconds, forever.
    _ct_sio.lines = []
    _ct_log.data += "before \x1b[" + "9" * 5000 + "mstill here\nthe next line\n"
    try:
        _ct_tick()
        _ct_wedge = None
    except Exception as _ct_exc:        # the poller swallows this and retries forever
        _ct_wedge = "%s: %s" % (type(_ct_exc).__name__, str(_ct_exc)[:80])
    check("console tick: a colour code too long to parse does not wedge the console",
          _ct_wedge is None and _ct_sio.lines == ["before still here", "the next line"],
          "tick raised %s; pushed %r" % (_ct_wedge, [l[:40] for l in _ct_sio.lines]))

    # A line that never ends must not be held forever. It grew by a whole read every tick.
    _ct_sio.lines = []
    _ct_log.data += "x" * 70000
    for _ in range(3):
        _ct_tick()
    check("console tick: an unterminated line past the cap is shown, not held without bound",
          len(_ct_sio.lines) == 1 and _ct_sio.lines[0] == "x" * 70000
          and not _bs_partial_state.get(_CT),
          "pushed %d line(s); still holding %d chars"
          % (len(_ct_sio.lines), len(_bs_partial_state.get(_CT) or "")))
    _ct_log.data += "\n"
    _ct_tick()
    _ct_sio.lines = []
    _ct_log.data += "half a li"
    _ct_tick()
    _ct_log.data += "ne\n"
    _ct_tick()
    check("console tick: (control) a SHORT fragment is still held and completed",
          _ct_sio.lines == ["half a line"], "pushed %r" % (_ct_sio.lines,))

    # Nobody watching: the offset goes, so reopening the console starts from NOW rather than
    # replaying everything written while it was closed as if it were live.
    _ct_sf._forget_unwatched_consoles([])
    _ct_sio.lines = []
    _ct_log.data += "".join("[04:%02d:00] written while nobody watched %d\n" % (i, i)
                            for i in range(50))
    _ct_tick()
    check("console tick: a console nobody watched does not replay its backlog on reopen",
          _ct_sio.lines == [], "replayed %d lines as live" % len(_ct_sio.lines))
    _ct_log.data += "[05:00:00] after reopening\n"
    _ct_tick()
    check("console tick: ...and streams what is written after it is reopened",
          _ct_sio.lines == ["[05:00:00] after reopening"], "pushed %r" % (_ct_sio.lines,))
    _ct_sf._forget_unwatched_consoles([_CT])
    check("console tick: (control) a WATCHED console keeps its offset",
          _CT in _ct_offsets, "the offset of a console someone has open was dropped")
finally:
    _sm_core.read_as_game_user, _ct_sf._host_timezone_cached = _ct_saved
    _ct_offsets.pop(_CT, None)
    _bs_partial_state.pop(_CT, None)

# ...and the poller really calls those two, every tick. Read as AST, not text: the comment
# explaining the fix names both functions.
import ast as _ct_ast
_ct_tree = _ct_ast.parse(_bs_src)
_ct_poller = next((n for n in _ct_ast.walk(_ct_tree)
                   if isinstance(n, _ct_ast.FunctionDef) and n.name == "console_poller"), None)
_ct_calls = {c.func.id for c in _ct_ast.walk(_ct_poller or _ct_ast.Module(body=[]))
             if isinstance(c, _ct_ast.Call) and isinstance(c.func, _ct_ast.Name)}
check("console poller: it drives _console_tick and forgets unwatched consoles",
      _ct_poller is not None and {"_console_tick", "_forget_unwatched_consoles"} <= _ct_calls,
      "console_poller calls %s" % sorted(_ct_calls))


# ── The panel must never OFFER to turn LinuxGSM's logtimestamp on ───────────────────────
# It works, and the cost is the live console. LinuxGSM builds the capture as
# `cat | gawk '{ print strftime(...), $0 }' >> consolelog`, and gawk writing to a FILE is BLOCK
# buffered, not line buffered: measured at 0 lines reaching the log after 33 lines of input,
# with everything appearing only once 4KB had accumulated. On a quiet server that is an
# apparently frozen console for hours, which is how it was reported. The pipeline is built in
# command_start.sh, so nothing in the panel can add an fflush or stdbuf.
#
# Shipped as a one-click offer before anyone measured that. The parsing stays (a log someone
# stamped by hand still reads correctly) and the OFF switch stays (anyone who turned it on
# needs the way back), but the invitation is gone and must not come back.
_sd_html = c.get("/server/%d" % gs_id).get_data(as_text=True)
check("log stamps: the page does not offer to TURN ON LinuxGSM's stamping",
      "enableLogTimestamps" not in _sd_html,
      "the enable control is back — it starves the live console (gawk block-buffers to a file)")
check("log stamps: ...but it does offer the way back OFF",
      "disableLogTimestamps" in _sd_html,
      "no way to turn it off — anyone who enabled it is stuck with a frozen console")
_sd_js_src = open(os.path.join(_repo_root, "static", "js", "server_detail.js"),
                  encoding="utf-8").read()
check("log stamps: and no JS path enables it either",
      "enabled: true" not in _sd_js_src.replace(" ", "").replace("enabled:true", "enabled: true"),
      "some JS still POSTs enabled:true to the log-timestamps endpoint")

# ── The Update button and the bulk endpoint must agree about who HAS an update ──────────
# They didn't. GameServer.supports_update knows the Call of Duty family is not SteamCMD-based
# and has no `update` command at all (_NO_UPDATE_GAMES exists for exactly that), and
# /api/servers/bulk-action asks it and skips those servers with "no update support". The
# control bar computed the same thing a second time, as `(not cmd_set) or ("update" in
# cmd_set)` — which for a server whose command list has not been fetched yet fails open for
# EVERY game, the cod family included.
#
# So the detail page offered Update on a cod server, accepted the click as a long action,
# answered "watch the live console for progress", ran a command LinuxGSM does not have, and
# threw the error away. One question, two answers, and the button had the wrong one.
with app.app_context():
    _su_remote_id = db.session.get(GameServer, gs_id).remote_id
    _su_cod = GameServer(remote_id=_su_remote_id, name="smoke-cod", short_name="cod4server",
                         game_type="cod4", port=28960, installed=True, status="offline")
    db.session.add(_su_cod)
    db.session.commit()
    _su_cod_id = _su_cod.id
    # No commands cached — the state a freshly imported or installed server is in, and the
    # only one where the two implementations differed.
    check("update button: (setup) the cod server has no cached command list",
          not db.session.get(GameServer, _su_cod_id).get_commands(),
          "it has one, so this proves nothing about the un-fetched case")
    check("update button: the model says a cod server has no update command",
          db.session.get(GameServer, _su_cod_id).supports_update is False,
          "the model thinks it does")
    check("update button: ...and a SteamCMD game with no cached list still fails open",
          db.session.get(GameServer, gs_id).supports_update is True,
          "hiding Update for a game that has one is the worse failure")
_su_html = c.get("/server/%d" % _su_cod_id).get_data(as_text=True)
check("update button: the cod server's control bar does NOT offer Update",
      'data-args=\'["update", "@self", false]\'' not in _su_html,
      "the button is there — clicking it runs a command LinuxGSM does not have")
_su_gmod_html = c.get("/server/%d" % gs_id).get_data(as_text=True)
check("update button: ...while a SteamCMD game's bar still does",
      'data-args=\'["update", "@self", false]\'' in _su_gmod_html,
      "Update vanished for a game that supports it")
# The two paths agree now, which is the actual property. Asked via the endpoint that reads
# the model, so a regression in either implementation shows up as a disagreement.
_su_bulk = (c.post("/api/servers/bulk-action",
                   json={"action": "update", "server_ids": [_su_cod_id, gs_id]}).get_json()
            or {})
_su_skipped = [x.get("server_id") for x in _su_bulk.get("skipped", [])]
_su_queued = [x.get("server_id") for x in _su_bulk.get("queued", [])]
check("update button: the bulk endpoint skips the same server the bar hides it for",
      _su_cod_id in _su_skipped and gs_id in _su_queued,
      "skipped=%s queued=%s" % (_su_skipped, _su_queued))
with app.app_context():
    db.session.delete(db.session.get(GameServer, _su_cod_id))
    db.session.commit()

# ── Which build of the game is installed ────────────────────────────────────────────────
# "Can you show the version of the game that's installed" — and no single source answers it
# for the games this panel manages. SteamCMD records an exact buildid on disk and the running
# game reports a friendlier string over its query protocol; the Call of Duty family has no
# SteamCMD install at all (it is in _NO_UPDATE_GAMES for the same reason), so for those the
# query is the ONLY answer that exists. Both are read, and the preference between them, the
# fallbacks, and what happens when neither answers are each asserted — "unknown" is a real
# outcome here and must not read as a confident wrong number.
from panel.ops.ssh_manager import game as _gv_mod
_gv_saved = _sm_core.run_command
_gv_rag_saved = _sm_core.run_as_game_user
_gv_mod.invalidate_game_version()
try:
    # The on-disk read parses the manifest ON THE HOST and prints key=value lines, so that is
    # what this stub answers. serverfiles/steamapps/ can hold a game's manifest and a
    # dependency's, and picking whichever globs first reports a build number that never moves
    # on an update: the third check below holds the read to the appid in LinuxGSM's own config.
    _gv_calls = []

    def _gv_disk(with_manifest=True, appid_in_cfg=True):
        def _rc(server, command, timeout=30, sudo=None):
            _gv_calls.append(command)
            if "appmanifest" in command:      # the on-disk read
                if not with_manifest:
                    return "", "", 0
                out = []
                if appid_in_cfg:
                    out.append("appid=4020")
                out += ["build=19765832", "updated=1757900000"]
                return "\n".join(out), "", 0
            if "gamedig" in command:          # the live query
                return "", "", 0
            return "", "", 0
        return _rc

    _sm_core.run_command = _gv_disk()
    with app.app_context():
        _gv_gs = db.session.get(GameServer, gs_id)
        _gv_remote, _gv_user = _gv_gs.remote, _gv_gs.short_name
        _gv1 = _gv_mod.game_version(_gv_remote, _gv_user, game_type=_gv_gs.game_type,
                                    port=_gv_gs.port, query_type="csgo",
                                    selfname=_gv_gs.lgsm_name, force=True)
    check("game version: the Steam build on disk is read when the game isn't answering",
          _gv1.get("build") == "19765832" and _gv1.get("label") == "build 19765832",
          "got %s" % _gv1)
    check("game version: the build is dated, so a stale install is visible as one",
          "files updated 2025-09-15 (UTC)" in (_gv1.get("detail") or ""),
          "got %r" % _gv1.get("detail"))
    check("game version: the appid comes from LinuxGSM's own config, not whichever "
          "manifest globs first",
          any("lgsm/config-lgsm/%s/_default.cfg" % _gv_gs.lgsm_name in _c for _c in _gv_calls),
          "commands were %s" % [_c[:80] for _c in _gv_calls])

    # The running game's own answer wins: it is the version players see, and it is the only
    # one a non-SteamCMD game has.
    def _gv_with_query(server, command, timeout=30, sudo=None):
        if "gamedig" in command:
            return "1.7", "", 0
        return _gv_disk()(server, command, timeout, sudo)

    _sm_core.run_command = _gv_with_query
    with app.app_context():
        _gv_gs = db.session.get(GameServer, gs_id)
        _gv2 = _gv_mod.game_version(_gv_remote, _gv_user, game_type=_gv_gs.game_type,
                                    port=_gv_gs.port, query_type="csgo",
                                    selfname=_gv_gs.lgsm_name, force=True)
    check("game version: the version the running game reports is what's shown",
          _gv2.get("label") == "1.7" and _gv2.get("reported") == "1.7", "got %s" % _gv2)
    check("game version: ...and the exact build is kept alongside it, not discarded",
          _gv2.get("build") == "19765832"
          and "Steam build 19765832" in (_gv2.get("detail") or ""), "got %s" % _gv2)

    # A game with neither: no SteamCMD manifest, not answering. The page must show nothing
    # rather than a number carried over from another server or another read.
    _sm_core.run_command = _gv_disk(with_manifest=False)
    with app.app_context():
        _gv_gs = db.session.get(GameServer, gs_id)
        _gv3 = _gv_mod.game_version(_gv_remote, _gv_user, game_type=_gv_gs.game_type,
                                    port=_gv_gs.port, query_type="csgo",
                                    selfname=_gv_gs.lgsm_name, force=True)
    check("game version: neither source answering is an empty label, not a wrong number",
          _gv3.get("label") == "" and not _gv3.get("build"), "got %s" % _gv3)

    # ...and that miss must not be CACHED: an unreachable host and a mid-install server both
    # look like this, and pinning "unknown" for the whole TTL outlasts either.
    _sm_core.run_command = _gv_with_query
    with app.app_context():
        _gv_gs = db.session.get(GameServer, gs_id)
        _gv4 = _gv_mod.game_version(_gv_remote, _gv_user, game_type=_gv_gs.game_type,
                                    port=_gv_gs.port, query_type="csgo",
                                    selfname=_gv_gs.lgsm_name)
    check("game version: a total miss isn't cached — the next read tries again",
          _gv4.get("label") == "1.7", "got %s" % _gv4)

    # A real answer IS cached (this page is opened a lot, the answer moves a few times a
    # year) — and an update has to drop it, or the panel shows the pre-update build forever.
    _gv_calls.clear()
    _sm_core.run_command = lambda *a, **k: (_gv_calls.append(1), ("", "", 0))[1]
    with app.app_context():
        _gv_gs = db.session.get(GameServer, gs_id)
        _gv5 = _gv_mod.game_version(_gv_remote, _gv_user, game_type=_gv_gs.game_type,
                                    port=_gv_gs.port, query_type="csgo",
                                    selfname=_gv_gs.lgsm_name)
    check("game version: a known answer is served from cache, with no SSH at all",
          _gv5.get("label") == "1.7" and not _gv_calls, "calls=%d %s" % (len(_gv_calls), _gv5))
    _gv_mod.invalidate_game_version(_gv_remote.id, _gv_user)
    with app.app_context():
        _gv_gs = db.session.get(GameServer, gs_id)
        _gv_mod.game_version(_gv_remote, _gv_user, game_type=_gv_gs.game_type,
                             port=_gv_gs.port, query_type="csgo",
                             selfname=_gv_gs.lgsm_name)
    check("game version: invalidating it forces a fresh read (what an update relies on)",
          bool(_gv_calls), "it still answered from cache")
    # An invalidation aimed at ANOTHER instance on the same host must not clear this one.
    _sm_core.run_command = _gv_with_query
    with app.app_context():
        _gv_gs = db.session.get(GameServer, gs_id)
        _gv_mod.game_version(_gv_remote, _gv_user, game_type=_gv_gs.game_type,
                             port=_gv_gs.port, query_type="csgo",
                             selfname=_gv_gs.lgsm_name, force=True)
    _gv_mod.invalidate_game_version(_gv_remote.id, "some-other-instance")
    _gv_calls.clear()
    _sm_core.run_command = lambda *a, **k: (_gv_calls.append(1), ("", "", 0))[1]
    with app.app_context():
        _gv_gs = db.session.get(GameServer, gs_id)
        _gv6 = _gv_mod.game_version(_gv_remote, _gv_user, game_type=_gv_gs.game_type,
                                    port=_gv_gs.port, query_type="csgo",
                                    selfname=_gv_gs.lgsm_name)
    check("game version: invalidating another instance on the host leaves this one cached",
          _gv6.get("label") == "1.7" and not _gv_calls, "calls=%d" % len(_gv_calls))

    # THE CALL SITE. Everything above passes just as well if nothing ever invokes the
    # invalidator — and then the panel serves the pre-update build for the rest of the TTL,
    # which is the one moment the number is guaranteed wrong. So run a real long action and
    # check the cached answer is gone afterwards. (A mutation removing the call from
    # _bg_action passed every other check in this block.)
    _sm_core.run_command = _gv_with_query
    with app.app_context():
        _gv_gs = db.session.get(GameServer, gs_id)
        _gv_mod.game_version(_gv_remote, _gv_user, game_type=_gv_gs.game_type,
                             port=_gv_gs.port, query_type="csgo",
                             selfname=_gv_gs.lgsm_name, force=True)
    check("game version: (setup) there is a cached answer for the update to drop",
          bool(_gv_mod._version_cache), "nothing cached — the next check proves nothing")
    _gv_done = []
    _sm_core.run_as_game_user = lambda *a, **k: (_gv_done.append(1), ("Update complete", "", 0))[1]
    try:
        with app.app_context():
            _gv_gs = db.session.get(GameServer, gs_id)
            app._run_action(_gv_gs, _gv_gs.remote, "update", None)
        _pa_wait(_gv_done)
        _gv_dl = _pt.time() + 5.0
        while _pt.time() < _gv_dl and _gv_mod._version_cache:
            _pt.sleep(0.02)
        check("game version: running an update drops the cached build it just changed",
              not _gv_mod._version_cache,
              "still cached after the update: %s" % dict(_gv_mod._version_cache))
    finally:
        _sm_core.run_as_game_user = _gv_rag_saved

    # Deleting the host must forget its versions. SQLite hands a deleted row's id to the next
    # INSERT, so a new host can arrive with the same id — and a cache keyed by host id would
    # then show ITS game the deleted one's build. An event on the row's deletion, so it holds
    # however the host is removed rather than only through the route that was remembered.
    _sm_core.run_command = _gv_with_query
    with app.app_context():
        _gv_dead = RemoteServer(name="gv-doomed", host="192.0.2.77", port=22,
                                username="root", auth_method="key", auth_credential="")
        db.session.add(_gv_dead)
        db.session.commit()
        _gv_dead_id = _gv_dead.id
        _gv_mod.game_version(_gv_dead, "gmodserver", game_type="gmod", port=27015,
                             query_type="csgo", selfname="gmodserver", force=True)
        check("game version: (setup) the doomed host has a cached version",
              any(k[0] == _gv_dead_id for k in _gv_mod._version_cache),
              "nothing cached for it — the check below proves nothing")
        db.session.delete(db.session.get(RemoteServer, _gv_dead_id))
        db.session.commit()
    check("game version: deleting a host forgets its versions (its id gets reused)",
          not any(k[0] == _gv_dead_id for k in _gv_mod._version_cache),
          "a recycled host id would inherit: %s" % dict(_gv_mod._version_cache))

    # The endpoint the page actually calls. It passes the server's OWN query_type through,
    # so set one — csgo has no entry in the built-in gamedig map, and without the override
    # the route would be asserting a short-circuit rather than the query.
    with app.app_context():
        db.session.get(GameServer, gs_id).query_type = "csgo"
        db.session.commit()
    _gv_mod.invalidate_game_version()
    _sm_core.run_command = _gv_with_query
    _gvj = (c.get("/api/server/%d/version" % gs_id).get_json() or {})
    check("version api: it answers with the label the page shows",
          _gvj.get("label") == "1.7" and _gvj.get("build") == "19765832", "got %s" % _gvj)
    # An unreachable host is the normal case for this endpoint, not a server error: it is
    # fetched on every load of a page that is otherwise fine, and a 500 there is noise in the
    # log and an error in the browser console for something that is only ever a nicety.
    #
    # TWO checks, because the first one alone was vacuous. game_version swallows an SSH
    # failure itself, so an unreachable host never reaches the route's own handler — the
    # assertion below held with that handler deleted. The second stubs the read to raise, and
    # is the one that actually exercises it.
    _gv_mod.invalidate_game_version()

    def _gv_boom(*a, **k):
        raise ConnectionError("host unreachable")

    _sm_core.run_command = _gv_boom
    _gvr = c.get("/api/server/%d/version" % gs_id)
    check("version api: an unreachable host is 200 with an empty label, not a 500",
          _gvr.status_code == 200 and (_gvr.get_json() or {}).get("label") == "",
          "got %s %s" % (_gvr.status_code, _gvr.get_json()))
    _gv_real = _gv_mod.game_version
    try:
        _gv_mod.game_version = _gv_boom
        _gvr2 = c.get("/api/server/%d/version" % gs_id)
        check("version api: ...and a read that RAISES is handled there too, not a 500",
              _gvr2.status_code == 200 and (_gvr2.get_json() or {}).get("label") == "",
              "got %s %s" % (_gvr2.status_code, _gvr2.get_json()))
    finally:
        _gv_mod.game_version = _gv_real
finally:
    _sm_core.run_command = _gv_saved
    _sm_core.run_as_game_user = _gv_rag_saved
    _gv_mod.invalidate_game_version()
    with app.app_context():
        db.session.get(GameServer, gs_id).query_type = None
        db.session.commit()

# ── /api/server/<id> reports the player count the rest of the panel uses ────────────────
# It used to run `cat <console_log> | grep -c '...'` over SSH and then look for a line holding
# both "players" and "has". grep -c prints a bare number, so the match was impossible: 0/0 for
# every server, forever, at the cost of a round trip that cats the whole console log.
from panel.core.panel_state import _player_counts as _pc_cache
_pc_cache[gs_id] = {"count": 7, "max": 24, "name": None, "ts": 9e9}
try:
    _ss = c.get("/api/server/%d" % gs_id)
    _ssj = _ss.get_json() or {}
    check("server status api: reports the cached player count, not 0",
          _ssj.get("player_count") == 7 and _ssj.get("max_players") == 24,
          "got %s/%s" % (_ssj.get("player_count"), _ssj.get("max_players")))
    _pc_cache.pop(gs_id, None)
    _ssj2 = (c.get("/api/server/%d" % gs_id).get_json() or {})
    check("server status api: an unknown count is null, not a confident 0",
          _ssj2.get("player_count") is None, "got %r" % _ssj2.get("player_count"))
finally:
    _pc_cache.pop(gs_id, None)
# Scanned across the whole source tree, not one file. This used to read app.py, and the code
# it guards against has not lived there for a long time — an absence assertion pointed at the
# wrong file passes no matter what the panel actually does.
_all_src, _all_unread = [], []
for _d, _, _fs in os.walk(_repo_root):
    # tests/smoke is this suite's own source (its parts are not named *_test.py), and this very
    # check spells the string it looks for.
    if any(_x in _d for _x in (".git", ".venv", "venv", "node_modules", "__pycache__", "/data",
                               os.path.join("tests", "smoke"))):
        continue
    for _f in _fs:
        if _f.endswith(".py") and not _f.endswith("_test.py"):
            try:
                _all_src.append(open(os.path.join(_d, _f), encoding="utf-8").read())
            except OSError as _e:
                _all_unread.append("%s (%s)" % (os.path.join(_d, _f), _e))
# An absence check passes for any file it could not read, so an unread file fails it.
check("server status api: no longer cats the console log to count players",
      not any("grep -c 'ClientConnect" in _x for _x in _all_src) and not _all_unread,
      "not read, so not scanned: %s" % _all_unread[:3])

# ── Editing a game server validates, and refuses a port change it cannot honour ────────
# /servers/<id>/edit wrote name, game_display and PORT straight from the form. The port write
# moved only the panel's record: the firewall rule and LinuxGSM stayed on the old port, and the
# monitor (`gs.port in <listening ports>`) then reported the server offline forever.
_es = c.post("/servers/%d/edit" % gs_id, data={"name": "renamed-cs", "game_display": "CS:GO"},
             headers={"X-Requested-With": "XMLHttpRequest"})
check("edit server: a valid rename succeeds", (_es.get_json() or {}).get("success") is True,
      _es.get_data(as_text=True)[:120])
with app.app_context():
    _g = db.session.get(GameServer, gs_id)
    check("edit server: ...and is persisted", _g.name == "renamed-cs" and _g.game_display == "CS:GO")
    _port_before = _g.port
_esb = c.post("/servers/%d/edit" % gs_id, data={"name": '<img src=x>', "game_display": ""},
              headers={"X-Requested-With": "XMLHttpRequest"})
check("edit server: a name with HTML metacharacters is refused",
      _esb.status_code == 400 and (_esb.get_json() or {}).get("success") is False)
_esp = c.post("/servers/%d/edit" % gs_id,
              data={"name": "renamed-cs", "port": str(_port_before + 1)},
              headers={"X-Requested-With": "XMLHttpRequest"})
check("edit server: a port change is refused rather than silently desyncing",
      _esp.status_code == 400 and "port can't be changed" in (_esp.get_json() or {}).get("message", ""),
      _esp.get_data(as_text=True)[:160])
with app.app_context():
    _g = db.session.get(GameServer, gs_id)
    check("edit server: ...and the stored port is untouched", _g.port == _port_before)
    _g.name = "smoke-cs"          # put the fixture back for the checks that follow
    db.session.commit()

# ── An edit that would leave no superadmin must really abort ───────────────────────────────
# The guard used to be the LAST thing in edit_user, after the password-reset and 2FA branches —
# and log_action() ends in db.session.commit(), so those branches had already committed the
# demotion by the time it looked. Its rollback then had nothing to undo: the route answered
# "That change would leave no active superadmin — aborted." with zero superadmins left and the
# web UI locked for everyone, recoverable only through manage.py.
#
# Both controls sit in ONE form in manage_users.html, so this is a single ordinary submit.
# Driven against a throwaway sole-superadmin so the suite's own fixtures stay intact.
with app.app_context():
    for _u in User.query.filter(User.is_superadmin.is_(True), User.is_active.is_(True)).all():
        _u.is_active = False            # park the real ones so `sole` really is sole
    _sole = User(username="smoke_sole", display_name="Sole",
                 password_hash=auth.hash_password("Str0ng!passw0rd"),
                 is_superadmin=True, is_active=True)
    db.session.add(_sole)
    db.session.commit()
    _sole_id = _sole.id
    _parked = [u.id for u in User.query.filter(User.is_superadmin.is_(True),
                                               User.is_active.is_(False)).all()]
_sc = client_as(_sole_id)
# No "reset_password" alongside it any more: resetting your OWN password from this form is
# refused outright (see the self-reset checks), so that refusal would answer first and this
# would pass without ever reaching the lockout guard.
_lr = _sc.post("/users/%d/edit" % _sole_id,
               data={"username": "smoke_sole"},   # superadmin UNticked
               headers={"X-Requested-With": "XMLHttpRequest"})
with app.app_context():
    _left = User.query.filter_by(is_superadmin=True, is_active=True).count()
    _row = db.session.get(User, _sole_id)
    check("edit user: an edit that would leave no superadmin really aborts",
          _left >= 1, "the panel was left with %d active superadmin(s)" % _left)
    check("edit user: ...and the row is unchanged, not half-committed",
          _row.is_superadmin and _row.is_active,
          "is_superadmin=%s is_active=%s" % (_row.is_superadmin, _row.is_active))
    check("edit user: the refusal is reported as one", _lr.status_code == 400
          and "no active superadmin" in (_lr.get_json() or {}).get("message", ""),
          "got %d %s" % (_lr.status_code, _lr.get_data(as_text=True)[:120]))
# A junk group id is a refusal, not a 500 — and must not have committed a password reset that
# the 500 then prevented anyone from ever seeing.
# On ANOTHER account: a self-reset is refused before this parse is reached.
with app.app_context():
    _jt = User(username="smoke_junkgrp", display_name="J", is_superadmin=False, is_active=True,
               password_hash=auth.hash_password("Str0ng!passw0rd"))
    db.session.add(_jt)
    db.session.commit()
    _jt_id = _jt.id
_jr = _sc.post("/users/%d/edit" % _jt_id,
               data={"username": "smoke_junkgrp", "is_active": "on",
                     "groups": "abc", "reset_password": "on"},
               headers={"X-Requested-With": "XMLHttpRequest"})
check("edit user: a non-numeric group id does not 500", _jr.status_code < 500,
      "got %d" % _jr.status_code)
check("edit user: ...and the reset password is actually handed back",
      bool((_jr.get_json() or {}).get("credential")), _jr.get_data(as_text=True)[:120])
with app.app_context():                 # restore the suite's own superadmins
    for _i in _parked:
        _u = db.session.get(User, _i)
        if _u:
            _u.is_active = True
    for _gone in (_sole_id, _jt_id):
        _s = db.session.get(User, _gone)
        if _s:
            db.session.delete(_s)
    db.session.commit()

# ── Renaming a group onto an existing name is a 400, not a 500 ─────────────────────
# Group.name is unique=True. add_group has always checked for the collision; edit_group did not,
# so a typo raised IntegrityError at commit.
with app.app_context():
    _ga = Group(name="smoke_dupe_a", description="", is_default=False)
    _gb = Group(name="smoke_dupe_b", description="", is_default=False)
    db.session.add_all([_ga, _gb])
    db.session.commit()
    _ga_id, _gb_id = _ga.id, _gb.id
_gd = c.post("/groups/%d/edit" % _gb_id, data={"name": "smoke_dupe_a", "description": ""},
             headers={"X-Requested-With": "XMLHttpRequest"})
check("edit group: a duplicate name is refused with a 400, not a 500",
      _gd.status_code == 400 and "already exists" in (_gd.get_json() or {}).get("message", ""),
      "status=%d" % _gd.status_code)
_gk = c.post("/groups/%d/edit" % _gb_id, data={"name": "smoke_dupe_b", "description": "same"},
             headers={"X-Requested-With": "XMLHttpRequest"})
check("edit group: keeping its OWN name is not a collision",
      (_gk.get_json() or {}).get("success") is True, _gk.get_data(as_text=True)[:120])
with app.app_context():
    for _gid in (_ga_id, _gb_id):
        _gg = db.session.get(Group, _gid)
        if _gg:
            db.session.delete(_gg)
    db.session.commit()


# ── A TOTP code is single-use on the password-change path too ────────────────────
# The login path has recorded the spent step since single-use was introduced; this — the panel's
# other route that accepts a live authenticator code — still asked the yes/no question, so an
# observed code stayed usable here for the rest of its ~90s window.
import pyotp as _pyotp
with app.app_context():
    _t = db.session.get(User, admin2_id)
    _t.last_totp_step = 0
    _t.password_hash = auth.hash_password("Str0ng!passw0rd")
    db.session.commit()
    _secret = _t.totp_secret_plain
_tc = client_as(admin2_id)
_code = _pyotp.TOTP(_secret).now()
_r1 = _tc.post("/account/password", data={"current_password": "Str0ng!passw0rd",
                                          "new_password": "Str0ng!passw0rd-2",
                                          "confirm_password": "Str0ng!passw0rd-2",
                                          "totp_code": _code})
# The status matters as much as the result. `u = current_user` kept the LocalProxy, and
# login_user(proxy) made flask-login store it as the session user — so the next current_user
# resolution recursed and the request died with a RecursionError, AFTER the new password was
# committed. A 500 on a password change that actually worked, with no audit entry.
check("password change: succeeds with a redirect, not a 500",
      _r1.status_code in (301, 302, 303), "status=%d" % _r1.status_code)
with app.app_context():
    _t = db.session.get(User, admin2_id)
    check("password change: a valid authenticator code is accepted",
          auth.check_password("Str0ng!passw0rd-2", _t.password_hash), "status=%d" % _r1.status_code)
    check("password change: ...and the step it used is recorded",
          (_t.last_totp_step or 0) > 0, "last_totp_step=%s" % _t.last_totp_step)
_tc2 = client_as(admin2_id)   # the change revoked the old session
_tc2.post("/account/password", data={"current_password": "Str0ng!passw0rd-2",
                                     "new_password": "Str0ng!passw0rd-3",
                                     "confirm_password": "Str0ng!passw0rd-3",
                                     "totp_code": _code})
with app.app_context():
    _t = db.session.get(User, admin2_id)
    check("password change: REPLAYING that same code is refused",
          auth.check_password("Str0ng!passw0rd-2", _t.password_hash),
          "the replayed code changed the password again")

# ── The API-token card is reachable, and the mint actually shows the token ────────────
# The Bearer path authenticates as its owner on every route (see the token checks above), but
# the account page had no way to mint or revoke one — and the mint route rendered a template
# that ignored `new_token`, so it stored a credential and threw the plaintext away.
_acct = c.get("/account").get_data(as_text=True)
check("account page: offers the API-token control", "api-token/generate" in _acct)
# ...and asks for the password on the way, because a token is a second credential that outlives
# the session that minted it. A bare POST — all a stolen cookie can manage — must mint nothing.
check("account page: the mint form asks for the password",
      'name="password"' in _acct.split("api-token/generate", 1)[1][:800],
      "the form posts with nothing but the session")
_bare = c.post("/account/api-token/generate", follow_redirects=True)
check("api token: a POST with no password mints nothing",
      _re_as.search(r"(lgsm_[0-9a-f]{48})", _bare.get_data(as_text=True) or "") is None,
      "status=%d" % _bare.status_code)
# ...and the refusal is RECORDED. log_action fired on the mint alone, so the one thing this
# gate produces that is worth watching — somebody in a borrowed session trying passwords
# against it, now the only way past — left no trace anywhere, while the mint they were aiming
# at left a tidy one. A gate with invisible refusals reports afterwards that nothing happened,
# which is exactly what it looks like when something did.
from panel.db.models import AuditLog as _at_AL  # pylint: disable=reimported
with app.app_context():
    _at_refused = _at_AL.query.filter_by(username="smoke_admin", action="api_token_generate",
                                         success=False).count()
check("api token: ...and that refusal is written to the audit log", _at_refused == 1,
      "%d refusals on record for smoke_admin, expected 1" % _at_refused)
# The label has to point AT the field it labels. This card copied the 2FA row's markup, which
# has a bare <label> and no ids, while the password-change form at the top of the same page
# wires for/id properly — so clicking the label did nothing and the box's only accessible name
# was a placeholder, which goes away the moment you type in it.
_mint_form = _acct.split("api-token/generate", 1)[1].split("</form>", 1)[0]
_mint_for = _re_as.search(r'<label[^>]*\sfor="([^"]+)"', _mint_form)
check("account page: the mint form's label points at its password field",
      bool(_mint_for) and ('id="%s"' % _mint_for.group(1)) in _mint_form,
      "label for=%r; ids in the form: %r" % (_mint_for and _mint_for.group(1),
                                             _re_as.findall(r'id="([^"]+)"', _mint_form)))
_mint = c.post("/account/api-token/generate", data={"password": "Str0ng!passw0rd"})
_mint_body = _mint.get_data(as_text=True)
_shown = _re_as.search(r"(lgsm_[0-9a-f]{48})", _mint_body)
check("api token: minting one SHOWS it (once)", _shown is not None, "status=%d" % _mint.status_code)
if _shown:
    check("api token: the token it showed actually authenticates",
          app.test_client().get("/api/servers", headers={
              "Authorization": "Bearer %s" % _shown.group(1)}).status_code == 200)
# ...and it is actually WRITTEN DOWN. Both checks above pass on a route whose
# `db.session.commit()` has been deleted: the mint and the Bearer read share one scoped
# session, so the query sees the pending write and the token authenticates for the rest of
# the process. Proven by mutation — with the commit removed, unit and smoke both stayed
# fully green. Drop the session first, so this reads what survived the request rather than
# what is still sitting in it: a credential the panel shows you once and forgets is worse
# than no credential at all.
if _shown:
    # Read it on a SEPARATE CONNECTION, which sees only what was committed — the checks above
    # cannot, because the mint and the Bearer read share one scoped session, so a token that
    # was never written would still authenticate for the rest of the process.
    #
    # Honest about what this does and does not prove: deleting the route's own
    # `db.session.commit()` does NOT make it fail, because log_action (panel/security/auth.py)
    # commits a few lines later and carries the write with it. So the explicit commit is
    # redundant today. That is exactly why the check is worth having — it pins the PROPERTY
    # (the credential the panel shows you once is on disk) rather than the call, and it will
    # fail if the audit line that happens to be carrying it ever moves or goes conditional.
    import sqlite3 as _tok_sql
    _tok_con = _tok_sql.connect(str(DB_PATH))
    try:
        _persisted = _tok_con.execute(
            "SELECT api_token FROM user WHERE id=?", (admin_id,)).fetchone()
    finally:
        _tok_con.close()
    check("api token: ...and it SURVIVES the request that minted it",
          bool(_persisted and _persisted[0]),
          "nothing committed to the row — the token the panel showed once is already gone")
check("account page: offers Revoke once a token exists", "api-token/revoke" in _mint_body)
_rev = c.post("/account/api-token/revoke", follow_redirects=True)
check("api token: revoking it works", _rev.status_code == 200)
if _shown:
    check("api token: ...and the revoked token stops authenticating",
          app.test_client().get("/api/servers", headers={
              "Authorization": "Bearer %s" % _shown.group(1)}).status_code != 200)

# ── An API token is a SECOND credential, and it has to answer to the controls that take an
# account back. It answered to none of them: it carries no auth_epoch, so a password change
# did not touch it, and "sign out everywhere" deleted every UserSession row and left it
# working. app.py's note that "cookie theft is also recoverable via sign out everywhere" was
# untrue while one existed — and minting one needed only a live session (no password, no 2FA),
# so an attacker holding a stolen cookie could leave themselves a key that survived the
# victim's entire recovery. Minting now costs the password (and a code when 2FA is on), which
# is why this POST carries one; the revocation reach below is what makes an already-minted
# token recoverable.
_tok_c = client_as(admin_id)
_mint2 = _tok_c.post("/account/api-token/generate", data={"password": "Str0ng!passw0rd"})
_m = _re_as.search(r"(lgsm_[0-9a-f]{48})", _mint2.get_data(as_text=True) or "")
check("api token: minted for the revocation tests", bool(_m),
      _mint2.get_data(as_text=True)[:120])
if _m:
    _tok = _m.group(1)
    _bearer = lambda: app.test_client().get(
        "/api/servers", headers={"Authorization": "Bearer %s" % _tok}).status_code
    check("api token: it authenticates before the revoke", _bearer() == 200)
    _tok_c.post("/account/sessions/revoke")
    check("api token: 'sign out everywhere' also revokes the API token", _bearer() != 200,
          "status=%s" % _bearer())
    # ...and every older smoke_admin cookie with it, the suite's own `c` included (a bare
    # "<id>" used to survive this; see the pre-epoch cookie check above). Re-issued.
    c = client_as(admin_id)

# The OTHER control that takes an account back. "Sign out everywhere" is asserted above; the
# password change was only ever claimed — in the mint's own rationale, which now rests on both
# being true. Nothing in the token carries an auth_epoch, so neither control reaches it by the
# sweep every session cookie gets: each route has an explicit revoke_api_token(), and deleting
# either one is silent. Its own account, because changing smoke_admin's password would pull the
# rug from under every later check that signs in as them.
with app.app_context():
    _pw_u = _TU(username="api_token_pwchg", display_name="Token PW",
                password_hash=auth.hash_password("Str0ng!passw0rd"),
                is_superadmin=False, is_active=True)
    db.session.add(_pw_u)
    db.session.commit()
    _pw_id = _pw_u.id
_pw_c = client_as(_pw_id)
_pw_mint = _pw_c.post("/account/api-token/generate", data={"password": "Str0ng!passw0rd"})
_pw_m = _re_as.search(r"(lgsm_[0-9a-f]{48})", _pw_mint.get_data(as_text=True) or "")
check("api token: minted for the password-change test", bool(_pw_m),
      "status=%d" % _pw_mint.status_code)
if _pw_m:
    def _pw_bearer():
        return app.test_client().get("/api/servers", headers={
            "Authorization": "Bearer %s" % _pw_m.group(1)}).status_code

    check("api token: it authenticates before the password change", _pw_bearer() == 200,
          "status=%s" % _pw_bearer())
    _pw_c.post("/account/password", data={"current_password": "Str0ng!passw0rd",
                                          "new_password": "Str0ng!passw0rd-2",
                                          "confirm_password": "Str0ng!passw0rd-2"})
    check("api token: a password change also revokes the API token", _pw_bearer() != 200,
          "status=%s — the token answers to no epoch, so only that route's explicit "
          "revoke_api_token() takes it away" % _pw_bearer())

# ── The 2FA branch of the mint, end to end — and the writes that have to SURVIVE the request
# Every mint above is smoke_admin's, and smoke_admin has no 2FA, so the block that burns a
# TOTP step and spends a one-time backup code ran against a hand-built stand-in in the unit
# suite and nothing else. What a stand-in cannot show is the half that makes either of those
# mean anything: the step and the spent code have to reach the DATABASE. If they don't, the
# replay guard is a per-request variable and a backup code is infinite — and the route reads
# exactly the same either way.
#
# Nor did anything assert that the mint persists what it hands out: deleting
# db.session.commit() from the route left both suites fully green, because log_action commits
# the same session one line later. So every assertion below re-reads the row in a FRESH app
# context — a new session, a real SELECT — after the POST has finished, instead of trusting
# the response that request returned.
import hashlib as _at_hashlib  # pylint: disable=reimported
with app.app_context():
    _at2_codes = auth.generate_backup_codes()
    _at2_secret = auth.generate_totp_secret()
    _at2 = _TU(username="api_token_2fa", display_name="Token 2FA",
               password_hash=auth.hash_password("Str0ng!passw0rd"),
               is_superadmin=False, is_active=True,
               totp_enabled=True, totp_secret=encrypt_secret(_at2_secret))
    _at2.set_backup_codes(_at2_codes)
    db.session.add(_at2)
    db.session.commit()
    _at2_id = _at2.id


def _at2_row():
    """(stored token digest, last spent step, backup codes left), as the DATABASE has them.

    A fresh app context on purpose: flask-sqlalchemy scopes its session to the app context, so
    this is a new session and a real read — not the writing request's own uncommitted work
    handed back from an identity map."""
    with app.app_context():
        _row = db.session.get(_TU, _at2_id)
        return (_row.api_token, _row.last_totp_step or 0, _row.backup_codes_remaining)


def _at2_shown_digest(body):
    """What the page showed, hashed the way the column stores it (or None if it showed none)."""
    _hit = _re_as.search(r"(lgsm_[0-9a-f]{48})", body or "")
    return _at_hashlib.sha256(_hit.group(1).encode()).hexdigest() if _hit else None


_at2_c = client_as(_at2_id)
_at2_page = _at2_c.get("/account").get_data(as_text=True)
_at2_form = _at2_page.split("api-token/generate", 1)[-1].split("</form>", 1)[0]
check("account page (2FA): the mint form asks for a code as well as the password",
      'name="totp_code"' in _at2_form, "the 2FA branch of the route can never be satisfied")
check("account page (2FA): ...and the code box has a name a screen reader can read",
      'aria-label="Code or backup code"' in _at2_form,
      "its only accessible name is the placeholder, which disappears as soon as you type")
# The password alone, with 2FA on — the proof account_2fa_disable refuses on the same page.
_at2_c.post("/account/api-token/generate", data={"password": "Str0ng!passw0rd"},
            follow_redirects=True)
_at2_tok, _at2_step, _at2_left = _at2_row()
check("api token (2FA): the password alone mints nothing", _at2_tok is None,
      "a token was stored anyway: %r" % (_at2_tok,))
check("api token (2FA): ...and nothing was written to the account either",
      _at2_step == 0 and _at2_left == len(_at2_codes),
      "last_totp_step=%r, %d of %d backup codes left" % (_at2_step, _at2_left, len(_at2_codes)))
# A REAL backup code with the wrong password. Counted, not re-checked: use_backup_code
# CONSUMES, so asking "is it still valid" would spend the thing being asked about.
_at2_c.post("/account/api-token/generate",
            data={"password": "wrong-password", "totp_code": _at2_codes[1]},
            follow_redirects=True)
_at2_tok, _, _at2_left = _at2_row()
check("api token (2FA): a valid code with the wrong password mints nothing",
      _at2_tok is None, "stored=%r" % (_at2_tok,))
check("api token (2FA): ...and that backup code was NOT spent on the failed attempt",
      _at2_left == len(_at2_codes),
      "%d of %d left — a one-time code was burnt by a request that failed for another reason"
      % (_at2_left, len(_at2_codes)))
# The real thing: password plus a live authenticator code.
_at2_code = _pyotp.TOTP(_at2_secret).now()
_r = _at2_c.post("/account/api-token/generate",
                 data={"password": "Str0ng!passw0rd", "totp_code": _at2_code})
_at2_first = _at2_shown_digest(_r.get_data(as_text=True))
check("api token (2FA): password + a live authenticator code mints one (positive control)",
      _at2_first is not None, "status=%d" % _r.status_code)
_at2_tok, _at2_step, _ = _at2_row()
check("api token (2FA): ...and the token it showed is IN THE ROW once the request is over",
      _at2_first is not None and _at2_tok == _at2_first,
      "shown=%r stored=%r — the plaintext was handed out and the database kept nothing"
      % (_at2_first, _at2_tok))
check("api token (2FA): ...and the step that code spent was committed with it",
      _at2_step > 0,
      "last_totp_step=%r — the replay guard is comparing against a value that never landed"
      % (_at2_step,))
# Which is what that step is FOR. A new request re-loads the user from the database, so the
# replay below is refused only if the step above really got there.
_r = _at2_c.post("/account/api-token/generate",
                 data={"password": "Str0ng!passw0rd", "totp_code": _at2_code},
                 follow_redirects=True)
# Both halves, not just the row: "the digest did not change" is also true of a route that
# stored nothing at all, so the response is asserted to have shown no token either.
_at2_replay = _at2_shown_digest(_r.get_data(as_text=True))
_at2_after, _, _ = _at2_row()
check("api token (2FA): REPLAYING that code mints nothing",
      _at2_replay is None and _at2_after == _at2_tok,
      "shown=%r, stored digest %s" % (_at2_replay,
                                      "changed" if _at2_after != _at2_tok else "held"))
# Somebody whose authenticator is gone is not locked out of their own token.
_r = _at2_c.post("/account/api-token/generate",
                 data={"password": "Str0ng!passw0rd", "totp_code": _at2_codes[0]})
_at2_second = _at2_shown_digest(_r.get_data(as_text=True))
check("api token (2FA): a one-time backup code mints one too", _at2_second is not None,
      "status=%d" % _r.status_code)
_at2_tok, _, _at2_left = _at2_row()
check("api token (2FA): ...and that mint replaced the stored digest",
      _at2_second is not None and _at2_tok == _at2_second,
      "shown=%r stored=%r" % (_at2_second, _at2_tok))
check("api token (2FA): ...and the code it spent is gone from the ROW, not just the request",
      _at2_left == len(_at2_codes) - 1, "%d of %d left" % (_at2_left, len(_at2_codes)))
_r = _at2_c.post("/account/api-token/generate",
                 data={"password": "Str0ng!passw0rd", "totp_code": _at2_codes[0]},
                 follow_redirects=True)
_at2_replay = _at2_shown_digest(_r.get_data(as_text=True))
_at2_after, _, _ = _at2_row()
check("api token (2FA): ...so replaying that backup code mints nothing",
      _at2_replay is None and _at2_after == _at2_tok,
      "shown=%r, stored digest %s" % (_at2_replay,
                                      "changed" if _at2_after != _at2_tok else "held"))
# Four refusals above, and a gate is only as useful as its record of them.
with app.app_context():
    _at2_refusals = _at_AL.query.filter_by(username="api_token_2fa",
                                           action="api_token_generate",
                                           success=False).count()
check("api token (2FA): every refusal above is in the audit log", _at2_refusals == 4,
      "%d recorded, expected 4 (no code, wrong password, replayed code, spent backup code)"
      % _at2_refusals)


# What later parts import from this one (`from smoke.part05 import ...`). The parts are
# one suite, run in order by tests/smoke_test.py; listing these here says so to a reader,
# and to CodeQL, which does not follow those imports and reads the names as unused.
__all__ = [
    'c',
]
