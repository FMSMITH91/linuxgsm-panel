"""Part 8 of the unit suite: GHSA-hh39-76g3-wxcx, behaviour. Imported for its side effects."""
# 2. BEHAVIOUR — every converted function, through a transport that RECORDS instead of sending:
# every unsafe name is refused, nothing reaches the transport, and the refusal reads as the
# function's own "could not run" — never as an empty, healthy answer. A plain name still sends its
# command, spelled exactly as the old builders spelled it. Then the builders themselves, and the
# review's F3 (a port stored as text) and F4 (a stored SSH login or host read as an ssh option).
# tests/unit/part07.py says what GHSA-hh39-76g3-wxcx was and holds the gates; part09 the data layer.
import io as _gh_io
import shlex as _gh_shlex

from unit.part01 import NS, _sm_core, _sm_cron, _sm_files, _sm_game, _sm_gmod, check, os  # noqa: E402

from panel.security import privileged as _gh_priv  # noqa: E402

_gh_sent = []
# What the recorded run_privileged answers crontab-list with. F3 swaps in a restart-check line.
_gh_crontab = {"text": "*/5 * * * * /home/gm2/gmodserver monitor > /dev/null 2>&1\n"}


def _gh_reply(cmd):
    if "common.cfg" in cmd:        # lgsm_get_values' framed read: a config that lets callers go on
        return ('querymode="2"\nquerytype="protocol-valve"\nqueryport="27015"\n'
                'servercfg="gmodserver.cfg"\n' + _sm_files._READ_END, "", 0)
    if cmd.startswith("id -gn"):
        return ("gmodcontent", "", 0)
    return ("", "", 0)


def _gh_run(server, cmd, timeout=30, sudo=None, stdin_text=None):
    _gh_sent.append(("run", cmd))
    return _gh_reply(cmd)


def _gh_privileged(server, verb, args=(), timeout=30, merge_stderr=True, sudo=True):
    # The REAL argument table, as on the wire: a verb it refuses raises and sends nothing.
    _gh_priv.check_args(verb, args)
    _gh_sent.append(("priv", verb, list(args)))
    if verb == "crontab-list":
        return (_gh_crontab["text"], "", 0)
    if verb == "content-game-present":
        return ("", "", 1)
    return ("", "", 0)


class _GhPopen:
    def __init__(self, argv, **k):
        _gh_sent.append(("popen", list(argv)))
        self.stdout = _gh_io.BytesIO(b"")
        self.stdin = _gh_io.BytesIO()

    def wait(self):
        return 0


class _GhChan(_gh_io.BytesIO):
    def write(self, *a):
        return 0

    def close(self):
        pass


class _GhOut(_gh_io.BytesIO):
    # A channel that has exited 0: the download streams check the exit status at EOF and close it.
    channel = NS(status_event=NS(wait=lambda _t=None: True), exit_status=0, close=lambda: None)


class _GhClient:
    def exec_command(self, cmd, timeout=None):
        _gh_sent.append(("exec", cmd))
        return _GhChan(), _GhOut(b""), _gh_io.BytesIO(b"")


import panel.routes._shared as _gh_shared  # noqa: E402
from panel.core import panel_state as _gh_ps  # noqa: E402

_GH_SAVED = [(_sm_core, n, getattr(_sm_core, n)) for n in (
    "run_command", "run_privileged", "_exec_local_argv", "helper_present",
    "get_connection", "_resolve_ts_host")]
_GH_SAVED += [(_sm_cron.subprocess, "Popen", _sm_cron.subprocess.Popen),
              (_sm_files.subprocess, "Popen", _sm_files.subprocess.Popen),
              (_sm_game.time, "sleep", _sm_game.time.sleep)]
_GH_SRV = NS(id=9101, is_local=False, auth_method="key", host="h", port=22, username="admin",
             sudo_enabled=True, name="h")
_GH_TS = NS(id=9102, is_local=False, auth_method="tailscale", host="h", port=22, username="admin",
            sudo_enabled=True, name="h")
_GH_LOCAL = NS(id=9103, is_local=True, auth_method="local", host="127.0.0.1", port=22,
               username="admin", sudo_enabled=True, name="h")
_GH_APP = NS(logger=NS(debug=lambda *a, **k: None))
# The advisory's own payload, and every other shape a name can break out, mislead sudo, or run long.
_GH_BAD = ["x; id > /tmp/pwned; #", "`id`", "$(id)", "a b", "-u root", "../x", "", "root", "#0",
           "gm2\n", None, "a" * 65, "x'y"]


def _gh_drain(u):
    _gh_ps._action_output[9104] = {"path": _gh_shared._action_log_path(u, "update"), "user": u, "pos": 0}
    try:
        return _gh_shared._drain_action_output(_GH_APP, _GH_SRV, 9104)
    finally:
        _gh_ps._action_output.pop(9104, None)


def _is_tuple_refusal(r):
    return isinstance(r, tuple) and len(r) == 3 and r[0] == "" and r[2] == 1


def _is_false_pair(r):
    return isinstance(r, tuple) and len(r) == 2 and r[0] is False


# (label, call(user, selfname), "the refusal reads as a refusal", script name in the body?, anchor)
_GH_TABLE = [
    ("_core.shell_as_game_user", lambda u, s: _sm_core.shell_as_game_user(_GH_SRV, u, "./%s x" % "gmodserver", selfname=s),
     _is_tuple_refusal, True, "./gmodserver x"),
    ("_core.read_as_game_user", lambda u, s: _sm_core.read_as_game_user(_GH_SRV, u, "tail -5 /tmp/f"),
     _is_tuple_refusal, False, "tail -5"),
    # ...and with a body that names the script, as the console reads' does (review F1).
    ("_core.read_as_game_user (selfname=)",
     lambda u, s: _sm_core.read_as_game_user(
         _GH_SRV, u, "tail -5 /home/%s/log/console/%s-console.log" % (u, s), selfname=s),
     _is_tuple_refusal, True, "-console.log"),
    ("_core.run_as_game_user", lambda u, s: _sm_core.run_as_game_user(_GH_SRV, u, "details", selfname=s),
     _is_tuple_refusal, True, "details"),
    ("_core.send_console_command", lambda u, s: _sm_core.send_console_command(_GH_SRV, u, "status", selfname=s),
     _is_tuple_refusal, True, "send-keys"),
    ("_core._rewrite_crontab", lambda u, s: _sm_core._rewrite_crontab(_GH_SRV, u, "-vF x", ["* * * * * true"]),
     _is_false_pair, False, "crontab"),
    ("_core.set_autostart", lambda u, s: _sm_core.set_autostart(_GH_SRV, u, True, s),
     _is_false_pair, True, "monitor"),
    ("_core.install_game_cron", lambda u, s: _sm_core.install_game_cron(_GH_SRV, u, s, {"monitor"}),
     _is_false_pair, True, "monitor"),
    ("_core.set_daily_restart", lambda u, s: _sm_core.set_daily_restart(_GH_SRV, u, s, "gmod", 27015),
     _is_false_pair, True, "restart-pending"),
    ("game.capture_console", lambda u, s: _sm_game.capture_console(_GH_SRV, u, s),
     _is_tuple_refusal, True, "capture-pane"),
    ("game._gamedig_player_list", lambda u, s: _sm_game._gamedig_player_list(_GH_SRV, u, "gmod", 27015),
     lambda r: r is None, False, "gamedig"),
    ("game.ensure_persistent_bans", lambda u, s: _sm_game.ensure_persistent_bans(_GH_SRV, u, s),
     lambda r: r is False, True, "banned_user"),
    ("game.run_game_backup", lambda u, s: _sm_game.run_game_backup(_GH_SRV, u, s, force=True),
     lambda r: r == (False, "invalid account or script name", False), True, "gmodserver backup"),
    ("game.list_server_commands", lambda u, s: _sm_game.list_server_commands(_GH_SRV, u, s),
     lambda r: r == [], True, "./gmodserver"),
    ("game._steam_build", lambda u, s: _sm_game._steam_build(_GH_SRV, u, s),
     lambda r: r == {}, True, "appmanifest"),
    ("game._queried_version", lambda u, s: _sm_game._queried_version(_GH_SRV, u, "gmod", 27015),
     lambda r: r == "", False, "gamedig"),
    ("cron._install_cron_runner", lambda u, s: _sm_cron._install_cron_runner(_GH_SRV, u),
     lambda r: r == 1, False, ".lgsm-cron"),
    ("cron._read_cron_status", lambda u, s: _sm_cron._read_cron_status(_GH_SRV, u),
     lambda r: r == {}, False, ".lgsm-cron"),
    ("cron.run_cron_job_now", lambda u, s: _sm_cron.run_cron_job_now(_GH_SRV, u, "* * * * * echo hi"),
     _is_false_pair, False, "setsid"),
    ("cron.list_game_backups", lambda u, s: _sm_cron.list_game_backups(_GH_SRV, u),
     lambda r: r is None, False, "lgsm/backup"),
    ("cron.prune_game_backups", lambda u, s: _sm_cron.prune_game_backups(_GH_SRV, u, 3),
     lambda r: r is False, False, "xargs -0"),
    ("cron.delete_game_backup", lambda u, s: _sm_cron.delete_game_backup(_GH_SRV, u, "gmodserver-2026.tar.gz"),
     lambda r: r is False, False, "rm -f --"),
    ("cron.stream_game_backup (paramiko)", lambda u, s: list(_sm_cron.stream_game_backup(_GH_SRV, u, "gmodserver-2026.tar.gz")),
     lambda r: r == [], False, "cat"),
    ("cron.stream_game_backup (tailscale)", lambda u, s: list(_sm_cron.stream_game_backup(_GH_TS, u, "gmodserver-2026.tar.gz")),
     lambda r: r == [], False, "cat"),
    ("cron.stream_game_backup (local, pre-helper argv)", lambda u, s: list(_sm_cron.stream_game_backup(_GH_LOCAL, u, "gmodserver-2026.tar.gz")),
     lambda r: r == [], False, "cat"),
    ("cron.player_count", lambda u, s: _sm_cron.player_count(_GH_SRV, u, "gmod", 27015),
     lambda r: r is None, False, "gamedig"),
    ("cron.player_slots", lambda u, s: _sm_cron.player_slots(_GH_SRV, u, "gmod", 27015),
     lambda r: r == (None, None, None), False, "gamedig"),
    ("cron.game_map", lambda u, s: _sm_cron.game_map(_GH_SRV, u, "gmod", 27999),
     lambda r: r == "", False, "gamedig"),
    ("cron.player_count_via_lgsm_query", lambda u, s: _sm_cron.player_count_via_lgsm_query(_GH_SRV, u, s, 27015),
     lambda r: r is None, True, "common.cfg"),
    ("cron.upgrade_managed_cron_tracking", lambda u, s: _sm_cron.upgrade_managed_cron_tracking(_GH_SRV, u, s, "gmod", 27015),
     lambda r: r is False, True, "crontab"),
    ("gmod.install_gmod_content", lambda u, s: _sm_gmod.install_gmod_content(_GH_SRV, u, ["cstrike"]),
     lambda r: isinstance(r, tuple) and r[0] is False and r[1] == [], False, "auto-install"),
    ("gmod.gmod_mount_setup", lambda u, s: _sm_gmod.gmod_mount_setup(_GH_SRV, u, "gmodcontent", ["cstrike"]),
     lambda r: r == (False, "invalid gmod user"), False, "mount.cfg"),
    ("gmod.gmod_mount_setup (the content account)",
     lambda u, s: _sm_gmod.gmod_mount_setup(_GH_SRV, "gm2", "gmodcontent" if u == "gm2" else u, ["cstrike"]),
     lambda r: r == (False, "invalid content user"), False, "mount.cfg"),
    # No `sudo -u` of its own (verbs only): held to "refused, nothing sent" and "a plain name runs".
    ("gmod.uninstall_gmod_content", lambda u, s: _sm_gmod.uninstall_gmod_content(_GH_SRV, u, ["cstrike"]),
     lambda r: isinstance(r, tuple) and r[0] is False and r[1] == [], False, None),
    # A mount check that could not run answers "restart needed" by design — see its docstring.
    ("gmod._mount_needs_restart", lambda u, s: _sm_gmod._mount_needs_restart(_GH_SRV, u),
     lambda r: r is True, False, "__LIVE__"),
    ("files.lgsm_read_config", lambda u, s: _sm_files.lgsm_read_config(_GH_SRV, u, s),
     lambda r: bool(r.get("error")), True, "config-lgsm"),
    ("files.lgsm_game_config", lambda u, s: _sm_files.lgsm_game_config(_GH_SRV, u, s),
     lambda r: bool(r.get("error")), True, "details"),
    ("files.lgsm_get_values", lambda u, s: _sm_files.lgsm_get_values(_GH_SRV, u, s, ["port"]),
     lambda r: r is None, True, "common.cfg"),
    ("files.lgsm_write_config", lambda u, s: _sm_files.lgsm_write_config(_GH_SRV, u, s, {"port": "1"}),
     _is_false_pair, True, "config-lgsm"),
    ("files.browse_dir", lambda u, s: _sm_files.browse_dir(_GH_SRV, u, "serverfiles"),
     lambda r: r is None, False, "find"),
    ("files.read_file", lambda u, s: _sm_files.read_file(_GH_SRV, u, "a.cfg"),
     lambda r: isinstance(r, tuple) and r[0] is None, False, "a.cfg"),
    ("files.stat_upload_targets", lambda u, s: _sm_files.stat_upload_targets(_GH_SRV, u, "", ["a.cfg"]),
     lambda r: r is None, False, "-maxdepth 1"),
    ("files.upload_file", lambda u, s: _sm_files.upload_file(_GH_SRV, u, "", "a.cfg", b"x", overwrite=True),
     _is_false_pair, False, "base64 -d"),
    ("files.delete_path", lambda u, s: _sm_files.delete_path(_GH_SRV, u, "a.cfg"),
     _is_false_pair, False, "rm"),
    ("files.stat_path", lambda u, s: _sm_files.stat_path(_GH_SRV, u, "a.cfg"),
     lambda r: r is None, False, "a.cfg"),
    ("files.stream_path (paramiko)", lambda u, s: list(_sm_files.stream_path(_GH_SRV, u, "a.cfg")),
     lambda r: r == [], False, "realpath"),
    ("routes._shared._looks_installed", lambda u, s: _gh_shared._looks_installed(_GH_APP, _GH_SRV, u, s),
     lambda r: r is None, True, "details"),
    # Registered and refused: it keeps the drain alive for the next tick, as a failed read always
    # has, and sends nothing.
    ("routes._shared._drain_action_output", lambda u, s: _gh_drain(u),
     lambda r: r is True, False, ".panel-update.log"),
]


def _gh_old_spelling(cmd):
    """What the builders spelled BY HAND before the helper, for the same account and body."""
    # That is f"sudo -u {user} bash -c {_quote(inner)}" or f"sudo -u {user} {_quote(arg)}…".
    argv = _gh_shlex.split(cmd)
    if argv[:2] != ["sudo", "-u"] or len(argv) < 4:
        return None
    if argv[3:5] == ["bash", "-c"] and len(argv) == 5:
        return "sudo -u %s bash -c %s" % (argv[2], _gh_shlex.quote(argv[4]))
    return "sudo -u %s %s" % (argv[2], " ".join(_gh_shlex.quote(a) for a in argv[3:]))


def _gh_command_texts(sent):
    """Every command TEXT that went out, whatever the transport."""
    out = []
    for rec in sent:
        if rec[0] in ("run", "exec"):
            out.append(rec[1])
        elif rec[0] == "popen":
            out.append(str(rec[1][-1]) if rec[1][0] == "ssh" else " ".join(map(str, rec[1])))
        elif rec[0] == "priv":
            out.append("%s %s" % (rec[1], " ".join(map(str, rec[2]))))
    return out


def _gh_stub_transports():
    """Point every transport the converted functions use at the recorder; _GH_SAVED undoes it."""
    _sm_core.run_command = _gh_run
    _sm_core.run_privileged = _gh_privileged
    _sm_core._exec_local_argv = lambda argv, **k: (_gh_sent.append(("argv", list(argv))), ("", "", 0))[1]
    # _gamedig_host is left REAL: it asks the host for its address over the recorded transport,
    # so a gamedig reader that forgets to refuse early is seen sending that too.
    _sm_core.helper_present = lambda recheck=False: False
    _sm_core.get_connection = lambda s, **k: _GhClient()
    _sm_core._resolve_ts_host = lambda s: "ts-host"
    _sm_cron.subprocess.Popen = _GhPopen
    _sm_files.subprocess.Popen = _GhPopen
    _sm_game.time.sleep = lambda s: None


def _gh_attempt(call, *args):
    """(call(*args), None) with the recorder emptied first — or (None, what it raised)."""
    _gh_sent.clear()
    try:
        return call(*args), None
    except Exception as e:        # a crash is not a refusal
        return None, e


def _gh_unsafe_runs(takes_self):
    """(account, script, as the script?, the name) for each unsafe name, as account and as script."""
    # "" and None as the SCRIPT mean "the account's own name" to every caller that takes one
    # (`selfname or user`), so they are unsafe only as the account.
    runs = []
    for name in _GH_BAD:
        runs.append((name, "gmodserver", False, name))
        if takes_self and name:
            runs.append(("gm2", name, True, name))
    return runs


def _gh_refusal_miss(name, as_self, r, exc, refused):
    """None when one unsafe-name run was a clean refusal (see _gh_check_refused); else what it did."""
    if exc is None and not _gh_sent and refused(r):
        return None
    if exc is not None:
        how = "raised %r" % exc
    elif _gh_sent:
        how = "SENT %r" % (_gh_command_texts(_gh_sent)[:1],)
    else:
        how = "returned %r, which is not this function's refusal" % (r,)
    return "%s=%r -> %s" % ("selfname" if as_self else "user", name, how)


def _gh_check_refused(label, call, refused, takes_self):
    """Every unsafe account (and script) name handed to `call` is refused, and nothing is sent."""
    bad_runs = []
    for user, script, as_self, name in _gh_unsafe_runs(takes_self):
        r, exc = _gh_attempt(call, user, script)
        miss = _gh_refusal_miss(name, as_self, r, exc, refused)
        if miss:
            bad_runs.append(miss)
    check("GHSA-hh39 %s: every unsafe account%s name is refused, as a refusal, and nothing is sent"
          % (label, "/script" if takes_self else ""),
          not bad_runs, "; ".join(bad_runs[:4]))


def _gh_sent_for_gm2(texts, sudo, anchor):
    """Every `sudo -u` text in `sudo` is for gm2, one names `anchor` (with none: anything went out)."""
    if not all(t.startswith("sudo -u gm") for t in sudo):
        return False
    return any(anchor in t for t in sudo) if anchor else bool(texts)


def _gh_check_plain(label, call, anchor):
    """...while a plain name still sends the command, spelled exactly as the old builders did."""
    err = _gh_attempt(call, "gm2", "gmodserver")[1]
    texts = _gh_command_texts(_gh_sent)
    sudo = [t for t in texts if t.startswith("sudo -u ")]
    respelled = [t for t in sudo if _gh_old_spelling(t) != t]
    check("GHSA-hh39 %s: ...while a plain name still sends its command, byte for byte as before"
          % label,
          err is None and not respelled and _gh_sent_for_gm2(texts, sudo, anchor),
          "raised=%r sent=%r respelled=%r" % (err, [t[:90] for t in texts][:4], respelled[:1]))


def _gh_builder_leak(builder, arg, kw):
    """None when `builder` refuses the names in `kw` with UnsafeGameAccount; else what it did."""
    try:
        builder(kw["user"], arg, selfname=kw.get("selfname"))
    except _sm_core.UnsafeGameAccount:
        return None
    except Exception as e:
        return "%s %r raised %r" % (builder.__name__, kw, e)
    return "%s %r BUILT a command" % (builder.__name__, kw)


def _gh_builder_leaks():
    """What either builder did with an unsafe account or script name, other than refuse it."""
    leaks = []
    # ...plus what a LOADED row can hold that a form never sends: SQLite hands a BLOB back as
    # bytes and an INTEGER as an int. Refused like any other bad name — not a TypeError.
    for name in _GH_BAD + [b"gm2", 7]:
        for kw in ({"user": name}, {"user": "gm2", "selfname": name}):
            if "selfname" in kw and not name:
                continue
            for builder, arg in ((_sm_core.game_user_cmd, "true"),
                                 (_sm_core.game_user_exec_cmd, ["true"])):
                leak = _gh_builder_leak(builder, arg, kw)
                if leak:
                    leaks.append(leak)
    return leaks


def _gh_check_builders():
    """The builders themselves: every unsafe name raises, and a plain one is the old text."""
    leaks = _gh_builder_leaks()
    check("GHSA-hh39 builders: every unsafe account or script name raises UnsafeGameAccount",
          not leaks, "; ".join(leaks[:4]))
    check("GHSA-hh39 builders: UnsafeGameAccount is a ValueError, so an existing `except ValueError` "
          "already treats it as bad input", issubclass(_sm_core.UnsafeGameAccount, ValueError))
    check("GHSA-hh39 builders: a plain name gives exactly the old hand-built text",
          _sm_core.game_user_cmd("gm2", "cd /home/gm2 && ./gmodserver details")
          == "sudo -u gm2 bash -c 'cd /home/gm2 && ./gmodserver details'"
          and _sm_core.game_user_exec_cmd("gm2", ["rm", "-f", "--", "/home/gm2/lgsm/backup/a.tar.gz"])
          == "sudo -u gm2 rm -f -- /home/gm2/lgsm/backup/a.tar.gz",
          repr((_sm_core.game_user_cmd("gm2", "x y"), _sm_core.game_user_exec_cmd("gm2", ["a b"]))))
    # Every argument WORD quoted, not only the account: the plain-name text above has no word that
    # needs it, so dropping the per-word quote passed the unit AND smoke suites. SCP:SL's EULA step
    # hands this a whole python program as one argument.
    words = ["printf", "%s\n", "a b", "$(id)", "x'y"]
    try:
        split = _gh_shlex.split(_sm_core.game_user_exec_cmd("gm2", words))
    except ValueError as e:
        split = repr(e)
    check("GHSA-hh39 builders: game_user_exec_cmd quotes every argument word, so each arrives whole",
          split == ["sudo", "-u", "gm2"] + words, repr(split))


def _gh_check_as_user_argv():
    """cron._as_user_argv refuses every unsafe name, and a plain one is the argv it always was."""
    argv_bad = []
    for name in _GH_BAD:
        try:
            _sm_cron._as_user_argv(name, "cat", "/x")
            argv_bad.append(repr(name))
        except _sm_core.UnsafeGameAccount:
            pass
    check("GHSA-hh39 cron._as_user_argv: an argv has no shell, but sudo still resolves the name — "
          "every unsafe one is refused", not argv_bad, ", ".join(argv_bad))
    check("GHSA-hh39 cron._as_user_argv: ...and a plain one is the same argv as before",
          _sm_cron._as_user_argv("gm2", "cat", "/x") == ["sudo", "-u", "gm2", "cat", "/x"])


# ── review F3: a port that is not a number never reaches the hourly restart line ──────────────
# GameServer.port is INTEGER, but SQLite keeps TEXT in it for a row written that way, and
# SQLAlchemy hands it back as a str. set_daily_restart interpolated it raw into a cron line
# /bin/sh runs as the account — the one gamedig caller in the tree without int(port).
_GH_TEXT_PORT = "27015; touch /tmp/ghsa-f3; true"
_GH_HEALED = "127.0.0.1:27015 2>/dev/null"


def _gh_f3(call, *args):
    """(result, exception or None, the command texts sent) for `call(*args)`."""
    r, e = _gh_attempt(call, *args)
    return r, e, _gh_command_texts(_gh_sent)


def _gh_check_f3_set_daily_restart():
    """F3 through set_daily_restart: text refused, nothing sent; a number, however stored, written."""
    r, e, t = _gh_f3(_sm_core.set_daily_restart, _GH_SRV, "gm2", "gmodserver", "gmod", _GH_TEXT_PORT)
    check("GHSA-hh39 F3 set_daily_restart: a port stored as text is refused, and nothing is sent",
          e is None and r == (False, "invalid port") and not t,
          "raised=%r returned=%r sent=%r" % (e, r, [x[:80] for x in t[:2]]))
    ok3 = []
    for port in (27015, "27015", 27015.0):     # the number, however SQLite handed it back
        r, e, t = _gh_f3(_sm_core.set_daily_restart, _GH_SRV, "gm2", "gmodserver", "gmod", port)
        ok3.append(e is None and r[0] is True and any(_GH_HEALED in x for x in t))
    check("GHSA-hh39 F3 set_daily_restart: ...while a numeric port still writes the line, as a number",
          all(ok3), repr(ok3))


def _gh_check_f3_upgrade():
    """F3 through the daily upgrade pass: text refused before any read; a number heals the line."""
    r, e, t = _gh_f3(_sm_cron.upgrade_managed_cron_tracking,
                     _GH_SRV, "gm2", "gmodserver", "gmod", _GH_TEXT_PORT)
    check("GHSA-hh39 F3 upgrade_managed_cron_tracking (daily, unattended): a text port is refused "
          "before the crontab is even read", e is None and r is False and not t,
          "raised=%r returned=%r sent=%r" % (e, r, [x[:80] for x in t[:2]]))
    r, e, t = _gh_f3(_sm_cron.upgrade_managed_cron_tracking, _GH_SRV, "gm2", "gmodserver", "gmod", 27015)
    check("GHSA-hh39 F3 upgrade_managed_cron_tracking: ...while a numeric one heals the line to it",
          e is None and r is True and any(_GH_HEALED in x for x in t),
          "raised=%r returned=%r sent=%r" % (e, r, [x[:80] for x in t[-2:]]))


def _gh_check_f3_builder():
    """F3 at the line's own builder, and cron_port's answer for an unset port."""
    bad3 = []
    for port in (_GH_TEXT_PORT, "0x10", 27015.5, True, [27015]):
        try:
            line = _sm_core.daily_restart_check_cmd("gm2", "gmodserver", "garrysmod", "1.2.3.4", port)
            bad3.append("%r built %r" % (port, line[-60:]))
        except ValueError:
            pass
    check("GHSA-hh39 F3 daily_restart_check_cmd: the line's own builder refuses what int() refuses "
          "(and a fractional or boolean port int() would quietly change)", not bad3,
          "; ".join(bad3))
    check("GHSA-hh39 F3 daily_restart_check_cmd: ...and writes the number it was given",
          "1.2.3.4:27015 2>" in _sm_core.daily_restart_check_cmd(
              "gm2", "gmodserver", "garrysmod", "1.2.3.4", " 27015"))
    unset = [_gh_f3(_sm_core.cron_port, v)[:2] for v in (None, "")]
    check("GHSA-hh39 F3 cron_port: an unset port (None or \"\") is None — not refused as text",
          unset == [(None, None), (None, None)], repr(unset))


def _gh_check_f3():
    """Review F3, with the recorded crontab holding a restart check the upgrade recognises."""
    saved = _gh_crontab["text"]
    _gh_crontab["text"] = "10 * * * * " + _sm_core.daily_restart_check_cmd(
        "gm2", "gmodserver", _sm_core.GAMEDIG_TYPE["gmod"], "127.0.0.1", 27999) + "\n"
    try:
        _gh_check_f3_set_daily_restart()
        _gh_check_f3_upgrade()
        _gh_check_f3_builder()
    finally:
        _gh_crontab["text"] = saved


# ── review F4: a stored SSH login or host never becomes an ssh OPTION ─────────────────────────
# Four argvs hand `<username>@<host>` to the system ssh client, and ssh reads an argument that
# begins with `-` as an option: username "-oProxyCommand=<cmd>" ran <cmd> on the panel's host.
# Each is driven with a hostile login and a hostile host, through the recorded Popen, and must
# refuse without spawning anything; a plain one must still spawn ssh with the destination
# after `--`.
from panel.ops import terminal_session as _gh_term     # noqa: E402


def _gh_ts(**kw):
    """A Tailscale host row, with `kw`'s fields in place of the defaults."""
    d = dict(id=9105, is_local=False, auth_method="tailscale", host="box.ts.net", port=22,
             username="admin", sudo_enabled=False, name="h", linuxgsm_user="")
    d.update(kw)
    return NS(**d)


_GH_SSH_BAD = [("username", "-oProxyCommand=touch /tmp/ghsa-f4"), ("username", "-l"),
               ("username", "root@evil"), ("username", "a b"), ("username", "admin\n"),
               ("host", "-oProxyCommand=touch /tmp/ghsa-f4"), ("host", "--"), ("host", "h;id"),
               ("host", "a b"), ("host", ""), ("port", "22 -oProxyCommand=x")]
_GH_SSH_SITES = [
    ("_core._run_via_ssh_cli (the Tailscale transport)",
     lambda srv: _sm_core._run_via_ssh_cli(srv, "echo hi", timeout=5, sudo=False),
     lambda r: r == ("", "invalid ssh login or host", -1)),
    ("cron.stream_game_backup (Tailscale)",
     lambda srv: list(_sm_cron.stream_game_backup(srv, "gm2", "gmodserver-2026.tar.gz")),
     lambda r: r == []),
    ("files.stream_path (Tailscale)",
     lambda srv: list(_sm_files.stream_path(srv, "gm2", "a.cfg")),
     lambda r: r == []),
    # Raises: terminal open() turns it into "Could not start a shell on …".
    ("terminal_session._open_tailscale (the web terminal)",
     lambda srv: _gh_term._open_tailscale(NS(), srv, 80, 24), None),
]


def _gh_ssh_miss(field, val, call, refused):
    """None when `call` refused a host whose `field` is `val` and spawned nothing; else what it did."""
    r, e = _gh_attempt(call, _gh_ts(**{field: val}))
    popen = [rec for rec in _gh_sent if rec[0] == "popen"]
    # With no `refused`, the site raises to refuse: UnsafeSshDestination is a ValueError.
    fine = isinstance(e, ValueError) if refused is None else (e is None and refused(r))
    if not popen and fine:
        return None
    return "%s=%r -> %s" % (field, val, ("SPAWNED %r" % (popen[0][1],)) if popen else
                            ("raised %r" % (e,)) if e else ("returned %r" % (r,)))


def _gh_check_ssh_refused(label, call, refused):
    """F4: a hostile stored login, host or port given to `call` is refused, and spawns nothing."""
    bad4 = [m for m in (_gh_ssh_miss(f, v, call, refused) for f, v in _GH_SSH_BAD) if m]
    check("GHSA-hh39 F4 %s: a hostile stored login, host or port is refused and nothing is "
          "spawned" % label, not bad4, "; ".join(bad4[:4]))


def _gh_check_ssh_plain(label, call):
    """F4: ...while a plain login still spawns ssh, with the destination after `--`."""
    # What is checked is the argv the recorded Popen was SPAWNED with. What the transport does
    # with that stand-in afterwards is not under test, so a raise is reported, not failed on.
    err = _gh_attempt(call, _gh_ts())[1]
    popen = [rec[1] for rec in _gh_sent if rec[0] == "popen"]
    argv = popen[0] if popen else []
    i = argv.index("--") if "--" in argv else -1
    check("GHSA-hh39 F4 %s: ...while a plain one still spawns ssh, the destination after `--`"
          % label, argv[:1] == ["ssh"] and i > 0
          and argv[i + 1:i + 2] == ["admin@box.ts.net"]
          and not any(a.startswith("-") for a in argv[i + 1:]),
          "argv=%r raised=%r" % (argv, err))


def _gh_open_fds():
    """How many file descriptors this process has open."""
    return len(os.listdir("/proc/self/fd"))


def _gh_check_terminal_fds():
    """F4: a login the terminal refuses leaks no descriptor."""
    # The terminal opened its pty BEFORE building the argv, so a refused argv would have leaked
    # both descriptors of the pair on every attempt. Counted, not assumed.
    fd0 = _gh_open_fds()
    # Refused (UnsafeSshDestination) — or, if it was not, whatever came next: the count says.
    raised = [_gh_attempt(_gh_term._open_tailscale, NS(), _gh_ts(username="-oProxyCommand=x"), 80, 24)[1]
              for _ in range(5)]
    check("GHSA-hh39 F4 terminal_session._open_tailscale: a refused login leaks no descriptor",
          _gh_open_fds() == fd0, "%d open before, %d after five refusals (raised: %s)"
          % (fd0, _gh_open_fds(), ", ".join(sorted({type(e).__name__ for e in raised}))))


def _gh_check_f4():
    """Review F4, over the four ssh argvs, with the stored host handed to ssh unresolved."""
    saved = _sm_core._resolve_ts_host
    _sm_core._resolve_ts_host = lambda srv: srv.host    # the stored host, unresolved
    try:
        for label, call, refused in _GH_SSH_SITES:
            _gh_check_ssh_refused(label, call, refused)
            if refused is not None:     # the terminal's plain case is part06's (a real pty)
                _gh_check_ssh_plain(label, call)
        check("GHSA-hh39 F4 terminal_session._ssh_argv: a plain login gets its argv, the destination "
              "after `--`", _gh_term._ssh_argv(_gh_ts())[-2:] == ["--", "admin@box.ts.net"],
              repr(_gh_term._ssh_argv(_gh_ts())))
        _gh_check_terminal_fds()
    finally:
        _sm_core._resolve_ts_host = saved


try:
    _gh_stub_transports()
    for _gh_label, _gh_call, _gh_refused, _gh_takes_self, _gh_anchor in _GH_TABLE:
        _gh_check_refused(_gh_label, _gh_call, _gh_refused, _gh_takes_self)
        _gh_check_plain(_gh_label, _gh_call, _gh_anchor)
    _gh_check_builders()
    _gh_check_as_user_argv()
    _gh_check_f3()
    _gh_check_f4()
finally:
    for _gh_mod, _gh_attr, _gh_val in _GH_SAVED:
        setattr(_gh_mod, _gh_attr, _gh_val)
    _gh_ps._action_output.pop(9104, None)


# ── ssh_manager review fixes (change_ssh_port's firewall, ufw/crontab locks, crontab rewrite,
#    password-auth fallthrough, cfg quoting, download streams, symlinked delete) ────────────────
# Each block drives the real function through a recording transport (or, where the fix IS a shell
# script, runs that script in bash against a stand-in `crontab` / a temporary home) and asserts on
# what reached the host — not on the text of the code.
import subprocess as _rv_sp  # noqa: E402
import tempfile as _rv_tf  # noqa: E402
import threading as _rv_th  # noqa: E402
import shutil as _rv_sh  # noqa: E402

from unit.part01 import _sm_hosts  # noqa: E402


def _rv_held_elsewhere(lk):
    """True when another thread cannot take `lk` right now (someone holds it)."""
    got = []

    def _try():
        ok = lk.acquire(blocking=False)
        got.append(ok)
        if ok:
            lk.release()
    t = _rv_th.Thread(target=_try)
    t.start()
    t.join()
    return got == [False]


# 1. change_ssh_port: step 1 opens only what is not already let in, and the revert closes only what
#    step 1 added. Every exit below is the sshd-validate failure, i.e. the revert path.
_RV_UFW = ("Status: active\n\n     To                         Action      From\n"
           "     --                         ------      ----\n%s")


def _rv_ufw_rows(*rows):
    return _RV_UFW % "".join("[%2d] %-26s %-11s Anywhere\n" % (i + 1, to, act)
                             for i, (to, act) in enumerate(rows))


def _rv_move(old_ports, new_port, bind="", status=None, status_rc=0):
    sent = []

    def _priv(server, verb, args=(), timeout=30, merge_stderr=True, sudo=True):
        sent.append((verb, list(args)))
        if verb == "ufw-status":
            return (status or "", "", status_rc)
        if verb == "listening-sockets":
            return ("tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n", "", 0)
        if verb == "sshd-validate":
            return ("", "bad config", 1)
        return ("", "", 0)
    saved = (_sm_core.run_privileged, _sm_core.write_root_file, _sm_hosts._sshd_socket_activated,
             _sm_hosts._sshd_current_ports, _sm_hosts._restart_ssh_listener)
    _sm_core.run_privileged = _priv
    _sm_core.write_root_file = lambda *a, **k: sent.append(("write",)) or ("", "", 0)
    _sm_hosts._sshd_socket_activated = lambda s: False
    _sm_hosts._sshd_current_ports = lambda s: list(old_ports)
    _sm_hosts._restart_ssh_listener = lambda *a, **k: None
    try:
        res = _sm_hosts.change_ssh_port(NS(id=8801, host="203.0.113.5", port=22, is_local=False,
                                           auth_method="key"), new_port, bind)
    finally:
        (_sm_core.run_privileged, _sm_core.write_root_file, _sm_hosts._sshd_socket_activated,
         _sm_hosts._sshd_current_ports, _sm_hosts._restart_ssh_listener) = saved
    ufw = [s for s in sent if s[0].startswith("ufw-") and s[0] != "ufw-status"]
    return res, ufw, sent


_rv_r, _rv_ufw, _ = _rv_move(["22"], 22, bind="203.0.113.5",
                             status=_rv_ufw_rows(("22/tcp", "LIMIT IN")))
check("change_ssh_port: a failed bind change on the port SSH already uses neither re-allows it "
      "(LIMIT kept) nor deletes it on the revert", _rv_r[0] is False and _rv_ufw == [],
      repr((_rv_r, _rv_ufw)))
_rv_r, _rv_ufw, _ = _rv_move(["22", "2222"], 2222, status=_rv_ufw_rows(("22/tcp", "LIMIT IN"),
                                                                        ("2222/tcp", "LIMIT IN")))
check("change_ssh_port: moving onto a port sshd already serves touches no ufw rule, reverted "
      "or not", _rv_r[0] is False and _rv_ufw == [], repr((_rv_r, _rv_ufw)))
_rv_r, _rv_ufw, _ = _rv_move(["22"], 2022, status=_rv_ufw_rows(("22/tcp", "ALLOW IN")))
check("change_ssh_port: a new port with no rule is allowed, and the revert closes exactly that",
      _rv_ufw == [("ufw-allow-proto-port", ["tcp", "2022", "SSH panel"]),
                  ("ufw-delete-allow-proto-port", ["tcp", "2022"])], repr(_rv_ufw))
_rv_r, _rv_ufw, _ = _rv_move(["22"], 2022, status=_rv_ufw_rows(("22/tcp", "ALLOW IN"),
                                                               ("2022/tcp", "ALLOW IN")))
check("change_ssh_port: a new port an existing rule already allows is left to it — not "
      "re-allowed, not deleted on the revert", _rv_ufw == [], repr(_rv_ufw))
_rv_r, _rv_ufw, _rv_sent = _rv_move(["22"], 2022, status=_rv_ufw_rows(("22/tcp", "ALLOW IN"),
                                                                      ("2022/tcp", "DENY IN")))
check("change_ssh_port: a port the firewall DENIES is refused before anything is written",
      _rv_r[0] is False and "blocked by the firewall rule" in _rv_r[1] and _rv_ufw == []
      and ("write",) not in _rv_sent, repr((_rv_r, _rv_sent)))
_rv_r, _rv_ufw, _ = _rv_move(["22"], 2022, status="Status: inactive\n")
check("change_ssh_port: on an inactive (unlistable) ufw the port is opened but the revert does "
      "not delete a rule that may have been there", _rv_ufw == [
          ("ufw-allow-proto-port", ["tcp", "2022", "SSH panel"])], repr(_rv_ufw))


# 2. ufw: every change runs under the host's ufw_lock, and remote_ufw_delete_rule holds it from its
#    guard's read to the delete — an insert from another thread lands after, not between.
_rv_srv = NS(id=8802, host="203.0.113.6", port=22, is_local=False, auth_method="key",
             username="admin")
_rv_seen = []
_rv_saved_rc = _sm_core.run_command


def _rv_rc(server, cmd, timeout=30, sudo=None, stdin_text=None):
    _rv_seen.append(_rv_held_elsewhere(_sm_core.ufw_lock(server)))
    return ("", "", 0)


_sm_core.run_command = _rv_rc
try:
    _sm_core.run_privileged(_rv_srv, "ufw-deny-ip", ["198.51.100.7", "panel-block"])
    _sm_core.run_privileged(_rv_srv, "ufw-status", ["numbered"])
finally:
    _sm_core.run_command = _rv_saved_rc
check("run_privileged: a ufw change runs under the host's ufw_lock; the read does not",
      _rv_seen == [True, False], repr(_rv_seen))

_rv_order = []
_rv_thr = []
_rv_saved = (_sm_core.run_privileged, _sm_hosts.firewall.remote_ufw_status)


def _rv_priv2(server, verb, args=(), timeout=30, merge_stderr=True, sudo=True):
    if _sm_core._ufw_mutating(verb):
        with _sm_core.ufw_lock(server):
            _rv_order.append(verb)
    else:
        _rv_order.append(verb)
    return ("", "", 0)


def _rv_status(server):
    # The auto-block inserting at 1 from its own thread, mid-check: it must wait for the delete.
    t = _rv_th.Thread(target=lambda: _sm_core.run_privileged(server, "ufw-deny-ip",
                                                             ["198.51.100.8", "auto-block"]))
    t.start()
    _rv_thr.append(t)
    t.join(0.3)
    _rv_order.append("read")
    return {"installed": True, "enabled": True,
            "groups": [{"key": "k3", "nums": [3], "protected": False}]}


_sm_core.run_privileged = _rv_priv2
_sm_hosts.firewall.remote_ufw_status = _rv_status
try:
    _rv_del = _sm_hosts.remote_ufw_delete_rule(_rv_srv, 3, expect_key="k3")
finally:
    for _t in _rv_thr:
        _t.join(5)
    _sm_core.run_privileged, _sm_hosts.firewall.remote_ufw_status = _rv_saved
check("remote_ufw_delete_rule: an insert racing the guard lands AFTER the delete, never between",
      _rv_del[0] is True and _rv_order == ["read", "ufw-delete-num", "ufw-deny-ip"],
      repr((_rv_del, _rv_order)))


# 3 + 4. The crontab rewrite, run for real in bash against a stand-in `crontab`.
_rv_ct = _rv_tf.mkdtemp(prefix="rv_ct_")
with open(os.path.join(_rv_ct, "crontab"), "w", encoding="utf-8") as _fh:
    _fh.write('#!/bin/sh\n'
              'if [ "$1" = "-l" ]; then\n'
              '  case "$CT_MODE" in\n'
              '    fail) echo "crontab: cannot talk to cron" >&2; exit 1 ;;\n'
              '    none) echo "no crontab for zz8" >&2; exit 1 ;;\n'
              '  esac\n'
              '  cat "$CT_STORE"; exit 0\n'
              'fi\n'
              'cp "$1" "$CT_STORE" && echo installed >> "$CT_STORE.log"\n')
os.chmod(os.path.join(_rv_ct, "crontab"), 0o755)


def _rv_crontab(mode, existing, call, tmpdir=None):
    store = os.path.join(_rv_ct, "store")
    with open(store, "w", encoding="utf-8") as fh:
        fh.write(existing)
    if os.path.exists(store + ".log"):
        os.unlink(store + ".log")
    held = []

    def _shell(server, user, sh, timeout=30, selfname=None):
        held.append(_rv_held_elsewhere(_sm_core.crontab_lock(server, user)))
        env = dict(os.environ, PATH=_rv_ct + ":" + os.environ.get("PATH", ""), CT_MODE=mode,
                   CT_STORE=store, TMPDIR=tmpdir or _rv_ct)
        p = _rv_sp.run(["bash", "-c", sh], capture_output=True, text=True, env=env, timeout=20)
        return p.stdout, p.stderr, p.returncode
    saved = _sm_core.shell_as_game_user
    _sm_core.shell_as_game_user = _shell
    try:
        res = call()
    finally:
        _sm_core.shell_as_game_user = saved
    with open(store, encoding="utf-8") as fh:
        now = fh.read()
    return res, now, os.path.exists(store + ".log"), held


_rv_srv3 = NS(id=8803, host="203.0.113.7", port=22, is_local=False, auth_method="key")
_rv_res, _rv_now, _rv_inst, _rv_held = _rv_crontab(
    "fail", "0 1 * * * keep-me\n",
    lambda: _sm_core._rewrite_crontab(_rv_srv3, "zz8", "", ["*/5 * * * * added"]))
check("_rewrite_crontab: a crontab -l that FAILED installs nothing and reports failure",
      _rv_res[0] is False and not _rv_inst and _rv_now == "0 1 * * * keep-me\n"
      and "could not read the crontab" in _rv_res[1], repr((_rv_res, _rv_now, _rv_inst)))
check("_rewrite_crontab: the rewrite runs under the account's crontab_lock", _rv_held == [True],
      repr(_rv_held))
_rv_res, _rv_now, _rv_inst, _ = _rv_crontab(
    "none", "", lambda: _sm_core._rewrite_crontab(_rv_srv3, "zz8", "", ["*/5 * * * * added"]))
check("_rewrite_crontab: an account with no crontab gets one with just the new line",
      _rv_res[0] is True and _rv_inst and _rv_now == "*/5 * * * * added\n", repr((_rv_res, _rv_now)))
_rv_res, _rv_now, _rv_inst, _ = _rv_crontab(
    "ok", "0 1 * * * a\n0 2 * * * b\n",
    lambda: _sm_core._rewrite_crontab(_rv_srv3, "zz8", "-vE '^'", ["0 3 * * * c"]))
check("_rewrite_crontab: a filter that drops EVERY line (grep exit 1) still installs the rest",
      _rv_res[0] is True and _rv_now == "0 3 * * * c\n", repr((_rv_res, _rv_now)))
_rv_res, _rv_now, _rv_inst, _ = _rv_crontab(
    "ok", "0 1 * * * a\n  0 2 * * * b\n",
    lambda: _sm_core._rewrite_crontab(_rv_srv3, "zz8", "", [], drop_line="0 2 * * * b"))
check("_rewrite_crontab: drop_line still removes the one line, everything else kept",
      _rv_res[0] is True and _rv_now == "0 1 * * * a\n", repr((_rv_res, _rv_now)))
_rv_res, _rv_now, _rv_inst, _ = _rv_crontab(
    "ok", "0 1 * * * keep-me\n",
    lambda: _sm_core._rewrite_crontab(_rv_srv3, "zz8", "", ["x"]),
    tmpdir=os.path.join(_rv_ct, "no-such-dir"))
check("_rewrite_crontab: no tempfile (mktemp failed) installs nothing",
      _rv_res[0] is False and not _rv_inst and _rv_now == "0 1 * * * keep-me\n",
      repr((_rv_res, _rv_now, _rv_inst)))

# The upgrade's read and rewrite are one step under the same lock.
_rv_upg = []
_rv_saved_up = (_sm_core.run_privileged, _sm_core._rewrite_crontab)


def _rv_up_priv(server, verb, args=(), timeout=30, merge_stderr=True, sudo=True):
    _rv_upg.append(("read", _rv_held_elsewhere(_sm_core.crontab_lock(server, "zz8"))))
    return ("*/5 * * * * /home/zz8/zz8 monitor > /dev/null 2>&1\n", "", 0)


def _rv_up_write(server, user, *a, **k):
    _rv_upg.append(("write", _rv_held_elsewhere(_sm_core.crontab_lock(server, user))))
    return True, ""


_sm_core.run_privileged, _sm_core._rewrite_crontab = _rv_up_priv, _rv_up_write
try:
    _sm_cron.upgrade_managed_cron_tracking(_rv_srv3, "zz8", "zz8")
finally:
    _sm_core.run_privileged, _sm_core._rewrite_crontab = _rv_saved_up
check("upgrade_managed_cron_tracking: the crontab read and its rewrite both run under the lock",
      _rv_upg == [("read", True), ("write", True)], repr(_rv_upg))
_rv_sh.rmtree(_rv_ct, ignore_errors=True)


# 5. A password remote with no usable password never signs in with the panel's own key; a named
#    key is the only key offered.
class _RvClient:
    def __init__(self):
        self.kw = None

    def connect(self, host, **kw):
        self.kw = kw


_rv_cl = _RvClient()
try:
    _sm_core._connect_by_auth_method(_rv_cl, NS(auth_method="password", host="203.0.113.8",
                                                port=22, username="root"), "", 5)
    _rv_err = None
except ConnectionError as _e:
    _rv_err = str(_e)
check("_connect_by_auth_method: password auth with an empty credential raises and never connects",
      bool(_rv_err) and "No usable SSH password" in _rv_err and _rv_cl.kw is None,
      repr((_rv_err, _rv_cl.kw)))
_rv_cl = _RvClient()
_sm_core._connect_by_auth_method(_rv_cl, NS(auth_method="key", host="203.0.113.8", port=22,
                                            username="root"), "/srv/keys/vps", 5)
check("_connect_by_auth_method: a named key is the only key — no agent, no ~/.ssh search",
      _rv_cl.kw["key_filename"] == "/srv/keys/vps" and _rv_cl.kw["allow_agent"] is False
      and _rv_cl.kw["look_for_keys"] is False, repr(_rv_cl.kw))
_rv_cl = _RvClient()
_sm_core._connect_by_auth_method(_rv_cl, NS(auth_method="key", host="203.0.113.8", port=22,
                                            username="root"), "", 5)
check("_connect_by_auth_method: a blank key path means the panel's own keys, still no agent",
      _rv_cl.kw["allow_agent"] is False and _rv_cl.kw["look_for_keys"] is True
      and _rv_cl.kw["key_filename"] == os.path.expanduser("~/.ssh/id_rsa"), repr(_rv_cl.kw))


# 6. LinuxGSM cfg values: written so bash reads back exactly what was typed (bar ${name}/$name
#    references), and _parse_cfg reads back what was written.
_rv_dir = _rv_tf.mkdtemp(prefix="rv_cfg_")
_rv_flag = os.path.join(_rv_dir, "pwned")
_rv_vals = {"a": 'p$1s$$`id`"q\\', "b": "$(touch %s)" % _rv_flag, "c": "-port ${port} +ip $ip",
            "d": "x${port@P}y", "e": "trail\\"}
_rv_lines = ['port="27015"', 'ip="0.0.0.0"']
_sm_files._apply_cfg_updates(_rv_lines, _rv_vals)
_rv_cfg = "\n".join(_rv_lines) + "\n"
with open(os.path.join(_rv_dir, "x.cfg"), "w", encoding="utf-8") as _fh:
    _fh.write(_rv_cfg)
_rv_p = _rv_sp.run(["bash", "-c", 'source "$1" && printf "%s\\0" "$a" "$b" "$c" "$d" "$e"', "_",
                    os.path.join(_rv_dir, "x.cfg")], capture_output=True, text=True, timeout=10)
_rv_got = _rv_p.stdout.split("\0")[:5]
check("_apply_cfg_updates: bash sources every value as typed — no command runs, ${port}/$ip live",
      _rv_p.returncode == 0 and _rv_got == [_rv_vals["a"], _rv_vals["b"], "-port 27015 +ip 0.0.0.0",
                                             _rv_vals["d"], _rv_vals["e"]]
      and not os.path.exists(_rv_flag), repr((_rv_p.returncode, _rv_got, _rv_p.stderr)))
_rv_parsed = _sm_files._parse_cfg(_rv_cfg)
check("_parse_cfg: reads back what _apply_cfg_updates wrote (so a re-save does not re-escape)",
      [_rv_parsed.get(k) for k in "abcde"] == [_rv_vals[k] for k in "abcde"], repr(_rv_parsed))
_rv_sh.rmtree(_rv_dir, ignore_errors=True)


# 7 + 8. Download streams: a reader that failed aborts the response at EOF; tar's "file changed"
#    exit 1 does not; the channel is closed and has an idle timeout; stdin/ConnectTimeout/-n.
class _RvProc:
    def __init__(self, chunks, rc):
        self._c, self._rc, self.stdout = list(chunks), rc, self

    def read(self, _n):
        return self._c.pop(0) if self._c else b""

    def close(self):
        pass

    def wait(self):
        return self._rc


def _rv_drain(gen, take=None):
    out = []
    try:
        for b in gen:
            out.append(b)
            if take is not None and len(out) >= take:
                gen.close()
                break
        return out, None
    except _sm_core.StreamFailed as e:
        return out, e


_rv_kw = {}
_rv_saved_popen = _sm_files.subprocess.Popen
_sm_files.subprocess.Popen = lambda argv, **k: _rv_kw.update(k) or _RvProc([b"ab", b"cd"], 1)
try:
    _rv_o1 = _rv_drain(_sm_files._stream_argv(["x"], "f", 2))
    _rv_o2 = _rv_drain(_sm_files._stream_argv(["x"], "f", 2, ok=(0, 1)))
    _rv_o3 = _rv_drain(_sm_files._stream_argv(["x"], "f", 2), take=1)
finally:
    _sm_files.subprocess.Popen = _rv_saved_popen
check("files._stream_argv: a reader exiting non-zero at EOF raises StreamFailed (download aborts)",
      _rv_o1[0] == [b"ab", b"cd"] and isinstance(_rv_o1[1], _sm_core.StreamFailed), repr(_rv_o1))
check("files._stream_argv: tar's exit 1 (a file changed while read) is a whole archive",
      _rv_o2 == ([b"ab", b"cd"], None), repr(_rv_o2))
check("files._stream_argv: a consumer that stops early (the size cap) is not a failure",
      _rv_o3 == ([b"ab"], None), repr(_rv_o3))

_rv_kw = {}
_sm_cron.subprocess.Popen = lambda argv, **k: _rv_kw.update(k) or _RvProc([b"zz"], 255)
try:
    _rv_o4 = _rv_drain(_sm_cron._stream_backup_argv(["ssh"], 2))
finally:
    _sm_cron.subprocess.Popen = _rv_saved_popen
check("cron._stream_backup_argv: stdin is DEVNULL and a failed read aborts the download",
      _rv_kw.get("stdin") == _rv_sp.DEVNULL and isinstance(_rv_o4[1], _sm_core.StreamFailed),
      repr((_rv_kw, _rv_o4)))


class _RvChan:
    def __init__(self, rc):
        self.exit_status, self.closed = rc, False
        self.status_event = _rv_th.Event()
        self.status_event.set()

    def close(self):
        self.closed = True

    def shutdown_write(self):
        pass


class _RvOut:
    def __init__(self, chunks, chan):
        self._c, self.channel = list(chunks), chan

    def read(self, _n):
        return self._c.pop(0) if self._c else b""


class _RvIn:
    def __init__(self, chan):
        self.channel = chan

    def write(self, _d):
        pass

    def flush(self):
        pass


class _RvSsh:
    def __init__(self, rc):
        self.chan, self.timeout = _RvChan(rc), "unset"

    def exec_command(self, cmd, timeout=None):
        self.timeout = timeout
        return _RvIn(self.chan), _RvOut([b"12", b"34"], self.chan), None


_rv_saved_gc = _sm_core.get_connection
_rv_c, _rv_c0 = _RvSsh(1), _RvSsh(0)
_sm_core.get_connection = lambda s: _rv_c
try:
    _rv_o5 = _rv_drain(_sm_files._stream_paramiko(_rv_srv, "cat", "f", 2))
    _sm_core.get_connection = lambda s: _rv_c0
    _rv_o6 = _rv_drain(_sm_cron.stream_game_backup(_rv_srv, "zz8", "zz8-2026-01-01-000000.tar.zst"))
finally:
    _sm_core.get_connection = _rv_saved_gc
check("files._stream_paramiko: idle timeout set, channel closed, a failed exit aborts the stream",
      _rv_c.timeout == _sm_core.STREAM_IDLE_TIMEOUT and _rv_c.chan.closed
      and isinstance(_rv_o5[1], _sm_core.StreamFailed), repr((_rv_c.timeout, _rv_o5)))
check("cron.stream_game_backup (paramiko): idle timeout, channel closed, a clean exit streams all",
      _rv_c0.timeout == _sm_core.STREAM_IDLE_TIMEOUT and _rv_c0.chan.closed
      and _rv_o6 == ([b"12", b"34"], None), repr((_rv_c0.timeout, _rv_o6)))

_rv_ts = NS(id=8804, host="box.ts.net", port=22, username="admin", auth_method="tailscale",
            is_local=False)
_rv_saved_ts = _sm_core._resolve_ts_host
_sm_core._resolve_ts_host = lambda s: s.host
try:
    _rv_a1 = _sm_cron._backup_read_argv(_rv_ts, "zz8", "n.tar.zst", "/home/zz8/lgsm/backup/n.tar.zst")
    _rv_a2 = _sm_files._ssh_download_argv(_rv_ts, "cat")
finally:
    _sm_core._resolve_ts_host = _rv_saved_ts
check("backup ssh argv: -n (reads no stdin) and a ConnectTimeout",
      "-n" in _rv_a1 and any(a.startswith("ConnectTimeout=") for a in _rv_a1), repr(_rv_a1))
check("download ssh argv: a ConnectTimeout (and no -n: the path goes on stdin)",
      "-n" not in _rv_a2 and any(a.startswith("ConnectTimeout=") for a in _rv_a2), repr(_rv_a2))


# 9. delete_path through a symlinked directory: the protected check is made on the host, on the
#    real parent + the name, in the same command as the rm. Run for real in a temporary "home".
_rv_home = _rv_tf.mkdtemp(prefix="rv_home_")
os.makedirs(os.path.join(_rv_home, "lgsm", "config-lgsm", "zz9server"))
os.makedirs(os.path.join(_rv_home, "junk"))
os.symlink("lgsm", os.path.join(_rv_home, "x"))
os.symlink(".", os.path.join(_rv_home, "dot"))


def _rv_home_shell(server, user, sh, timeout=30, selfname=None):
    p = _rv_sp.run(["bash", "-c", sh.replace("/home/zz9", _rv_home)], capture_output=True,
                   text=True, timeout=20)
    return p.stdout, p.stderr, p.returncode


_rv_saved_sh = _sm_core.shell_as_game_user
_sm_core.shell_as_game_user = _rv_home_shell
try:
    _rv_d1 = _sm_files.delete_path(_rv_srv, "zz9", "x/config-lgsm", selfname="zz9server")
    _rv_d2 = _sm_files.delete_path(_rv_srv, "zz9", "dot/lgsm", selfname="zz9server")
    _rv_d3 = _sm_files.delete_path(_rv_srv, "zz9", "x", selfname="zz9server")
    _rv_d4 = _sm_files.delete_path(_rv_srv, "zz9", "junk", selfname="zz9server")
finally:
    _sm_core.shell_as_game_user = _rv_saved_sh
_rv_lgsm_ok = os.path.isdir(os.path.join(_rv_home, "lgsm", "config-lgsm", "zz9server"))
check("delete_path: lgsm/ reached through a symlinked directory is refused as protected",
      _rv_d1[0] is False and _rv_d2[0] is False and "protected" in _rv_d1[1]
      and "protected" in _rv_d2[1] and _rv_lgsm_ok, repr((_rv_d1, _rv_d2, _rv_lgsm_ok)))
check("delete_path: deleting the symlink itself removes the link, never the tree it points at",
      _rv_d3 == (True, "Deleted") and not os.path.lexists(os.path.join(_rv_home, "x"))
      and _rv_lgsm_ok, repr(_rv_d3))
check("delete_path: an ordinary directory is still deleted",
      _rv_d4 == (True, "Deleted") and not os.path.exists(os.path.join(_rv_home, "junk")),
      repr(_rv_d4))
_rv_sh.rmtree(_rv_home, ignore_errors=True)
