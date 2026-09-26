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


class _GhClient:
    def exec_command(self, cmd):
        _gh_sent.append(("exec", cmd))
        return _GhChan(), _gh_io.BytesIO(b""), _gh_io.BytesIO(b"")


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
