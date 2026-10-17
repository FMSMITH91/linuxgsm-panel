"""Part 76 of the unit suite: review 1012d's core, ssh-core, system and reboot fixes (builder A).

Held here, each against the code path the finding named:

* the host and game samplers, the Remotes card, the panel host's own card and the specs probe read
  RAM, uptime, disk and the CPU from a host whose locale translates `free`, `uptime`, `df` and
  `lscpu`; a privileged verb rendered as shell (a remote, or the panel host before its helper)
  runs in C.UTF-8, as the helper runs it, so `ufw status` is read in English; so do the commands
  read by their words that are not verbs (`apt list --upgradable`, the install's account switch);
* a failed install the reconciler finds installed sheds its recorded reason;
* a custom-command template holding DEL is refused at save, as every press would refuse it;
* a LinuxGSM command in flight fails its reboot row after a day even with out-of-window ticks in
  between, and an outcome that is not a wait restarts that clock;
* the login-link Tailscale join writes both forwarding families, and logs a write that failed;
* the daily cron pass and the port resync rewrite a crontab only as an account cleared for writes;
* a fail2ban reload that failed on the panel host is retried by the next call;
* a failed paramiko exec closes its channel; an infinite port row is "no port", never a raise.

The HTTP error translations are driven in the smoke suite (tests/smoke/part04.py), whose app is
built by create_app and so carries the error handler this part's app does not register.

HOW IT RUNS. Pure functions, part12's Flask app and database, stand-ins through part20's _patch
(undone at the end of each block), and a real bash over this part's own stand-in programs.
Nothing touches the network, sudo, a real host or the checkout's data/.
"""
import os as _os76
import shutil as _shutil76
import subprocess as _sp76  # nosec B404 - runs bash on the panel's own command text
import tempfile as _tf76
import types as _types76

import app as _app76
from unit.part01 import check
from unit.part12 import (P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_delete_server, _p9_new_server, _p9_row,
                         _p9_set)
from unit.part20 import _patch, _patched
from panel.core import i18n as _i18n76
from panel.ops import system_ops as _so76
from panel.ops.ssh_manager import _core as _smc76
from panel.ops.ssh_manager import cron as _smcron76
from panel.ops.ssh_manager import firewall as _smf76
from panel.ops.ssh_manager import game as _smg76
from panel.ops.ssh_manager import hosts as _smh76
from panel.routes import _shared as _sh76
from panel.routes import manage_servers as _ms76
from panel.services import game_ports as _gp76
from panel.services import host_reboot as _hr76
from panel.services import reboot_words as _rw76

NS = _types76.SimpleNamespace
_TMP76 = _os76.path.realpath(_tf76.mkdtemp(prefix="lgsm-unit-p76-"))
# part12's transport tripwire is armed first in every block below (review 1013a: this was the one
# part since part49 that drove part12's app with none, and _node_tools_cron_pass swallows what it
# raises), so a host call a block did not stub is named by the check at the end of the part.
_TRIP76_START = len(_P9_TRIPPED)


def _arm76():
    """Arm the tripwire with part20's _patch: undone when the enclosing _patched() block ends."""
    _p9_arm(_patch, "part76")


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. A host whose locale translates the tools the panel reads
# ════════════════════════════════════════════════════════════════════════════════════════════════
# procps-ng's own catalogs turn free's "Mem:" into "Speicher:" (de), "Pamięć:" (pl), "Minne:" (sv);
# util-linux turns lscpu's "Model name:" into "Modellname:"; ufw's "Status: active" is "Status: aktiv".
# Each stand-in below answers the way gettext would: English when the message locale is C/POSIX,
# else LANGUAGE when it is set (gettext honours it over LC_ALL unless the locale is plain C), else
# the locale itself. The host's environment is a German Ubuntu's (/etc/default/locale sets both).
_BIN76 = _os76.path.join(_TMP76, "bin")
_os76.makedirs(_BIN76)
_GETTEXT76 = ('loc="${LC_ALL:-${LC_MESSAGES:-$LANG}}"; '
              'case "$loc" in C|POSIX) de=0 ;; *) case "${LANGUAGE:-$loc}" in de*) de=1 ;; *) de=0 ;; esac ;; esac; ')
_STANDINS76 = {
    "free": _GETTEXT76 + (
        'if [ "$de" = 1 ]; then w=Speicher:; else w=Mem:; fi; '
        'echo "               total        used        free      shared  buff/cache   available"; '
        'echo "$w     8000000000  3000000000  1000000000    10000000  4000000000  5000000000"'),
    "uptime": _GETTEXT76 + 'if [ "$de" = 1 ]; then echo "seit 3 Tagen"; else echo "up 3 days"; fi',
    "lscpu": _GETTEXT76 + (
        'if [ "$de" = 1 ]; then echo "Modellname:  P76 CPU"; echo "Maximale Taktfrequenz der CPU: 4200,0"; '
        'else echo "Model name:  P76 CPU"; echo "CPU max MHz: 4200.0000"; fi'),
    "ufw": _GETTEXT76 + 'if [ "$de" = 1 ]; then echo "Status: aktiv"; else echo "Status: active"; fi',
    # apt's own catalog; `apt list` is run by run_command / _run, not as a privileged verb.
    "apt": _GETTEXT76 + (
        'if [ "$de" = 1 ]; then echo "Auflistung…"; w="aktualisierbar von"; '
        'else echo "Listing..."; w="upgradable from"; fi; '
        'echo "p76lib/noble-updates 2.0-1 amd64 [$w: 1.0-1]"'),
    # The OS-update check's upgrade simulation (part100 drives its German reading): it installs
    # p76lib, so nothing is held back — and never the real apt-get or dpkg of the suite's machine.
    "apt-get": ('echo "NOTE: This is only a simulation!"; '
                'echo "Inst p76lib [1.0-1] (2.0-1 Ubuntu:24.04/noble-updates [amd64])"'),
    "dpkg": "echo amd64",
    # sudo's catalog (the language pack's sudo.mo): an account created a moment ago is not yet
    # resolvable on the first try. Logs each call to sudo.log and refuses only the first one.
    "sudo": _GETTEXT76 + (
        'echo "$*" >> "$HOME/sudo.log"; '
        'if [ "$(wc -l < "$HOME/sudo.log")" = 1 ]; then '
        'if [ "$de" = 1 ]; then echo "sudo: Unbekannter Benutzer $2" >&2; '
        'else echo "sudo: unknown user $2" >&2; fi; exit 1; fi; echo "p76 lgsm ran"'),
}
for _name76, _body76 in _STANDINS76.items():
    _path76 = _os76.path.join(_BIN76, _name76)
    with open(_path76, "w", encoding="utf-8") as _fh76:
        _fh76.write("#!/bin/bash\n" + _body76 + "\n")
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stand-in program this part runs
    _os76.chmod(_path76, 0o700)
_GERMAN_ENV76 = {"PATH": _BIN76 + ":/usr/bin:/bin", "LANG": "de_DE.UTF-8", "LANGUAGE": "de_DE:de",
                 "HOME": _TMP76}


def _bash76(command, *_a, **_k):
    """(out, err, rc) of `command` in a real bash on the German host. Any transport's stand-in."""
    r = _sp76.run(["/bin/bash", "-c", command],  # nosec B603 - bash on this repo's own command text
                  env=_GERMAN_ENV76, capture_output=True, text=True, timeout=30, check=False)
    return r.stdout.strip(), r.stderr.strip(), r.returncode


def _bash_on76(_server, command, *_a, **_k):
    """_bash76 in run_command's shape: (server, command, ...)."""
    return _bash76(command)


_ram76 = _smc76._parse_host_sample(_bash76(_smc76._host_sample_cmd())[0])[0]
_gram76 = _smc76._parse_game_sample(_bash76(_smc76._game_sample_cmd(None, None))[0])
check("live metrics: on a German-locale host the host and game samplers still read RAM (free's "
      "translated `Speicher:` line left ram_total at 0, the panel's 'not read' sentinel)",
      _ram76["ram_total"] == 8000000000 and _gram76["ram_total"] == 8000000000,
      repr((_ram76["ram_total"], _gram76["ram_total"])))

with _patched():
    _arm76()
    _patch(_smc76, "run_command", _bash_on76)
    _up76 = _smh76.remote_uptime(NS(id=-76), force=True)
    _specs76 = _smf76._compute_host_specs(NS(id=-76))
    _patch(_so76, "_run", _bash76)
    _local76 = _so76.server_uptime()
check("Remotes card and panel-host card: memory, its percent and the uptime are read on a German "
      "host (the awk on `Mem:` printed nothing, so the card said '?')",
      _up76["memory"] != "?" and _up76["memory_percent"] != "?" and _up76["uptime"] == "3 days"
      and _local76["memory"] != "?" and _local76["memory_percent"] != "?" and _local76["uptime"] == "3 days",
      repr((_up76, _local76)))
check("host specs: the CPU model and its max clock are read from lscpu on a German host",
      "P76 CPU" in repr(_specs76) and "4.2" in repr(_specs76), repr(_specs76))

# A privileged verb rendered as shell: on a remote, and on the panel host before its helper exists.
with _patched():
    _arm76()
    _patch(_smc76, "is_local_server", lambda s: False)
    _patch(_smc76, "run_command", _bash_on76)
    _rem_ufw76 = _smc76.run_privileged(NS(id=-76, name="p76"), "ufw-status", ["verbose"])
with _patched():
    _arm76()
    _patch(_smc76, "is_local_server", lambda s: True)
    _patch(_smc76, "helper_present", lambda recheck=False: False)
    _patch(_smc76, "_run_local", _bash76)
    _loc_ufw76 = _smc76.run_privileged(NS(id=-76, name="p76"), "ufw-status", ["verbose"])
check("privileged verbs: `ufw status` rendered as shell runs in C.UTF-8 as the helper's child does, "
      "on a remote and on a panel host without the helper (a German host printed `Status: aktiv`, "
      "and an active firewall with no rules read as off)",
      _rem_ufw76[0] == "Status: active" and _loc_ufw76[0] == "Status: active"
      and _so76.ufw_status_active(_rem_ufw76[0]), repr((_rem_ufw76, _loc_ufw76)))

# Commands the panel reads by their words that are NOT privileged verbs, so builder A's pin on the
# verb paths never reached them: `apt list --upgradable` on the panel host and on a remote, and the
# sudo that switches to a just-created game account during an install.
_osu_cmds76 = []
with _patched():
    _arm76()
    _patch(_so76, "_run", lambda cmd, *a, **k: _osu_cmds76.append(cmd) or _bash76(cmd))
    _osu_local76 = _so76.os_update_available(refresh=False)
with _patched():
    _arm76()
    _patch(_smc76, "run_privileged", lambda *a, **k: ("", "", 0))
    _patch(_smc76, "run_command", _bash_on76)
    _osu_remote76 = _smh76.remote_os_check_updates(NS(id=-76, name="p76"))
check("OS updates: on a German host `apt list --upgradable` is read with each package's old "
      "version, on the panel host and on a remote (apt's `[aktualisierbar von: …]` left every "
      "\"from\" empty, and the card showed only the new version)",
      [(p["name"], p["version"], p["from"]) for p in _osu_local76["packages"]] == [("p76lib", "2.0-1", "1.0-1")]
      and [(p["name"], p["version"], p["from"]) for p in _osu_remote76["packages"]]
      == [("p76lib", "2.0-1", "1.0-1")] and _osu_local76["ok"] and _osu_remote76["ok"]
      # the panel host spells the prefix out (its _run takes only literals): it must stay _core's
      and _osu_cmds76[:1] == [_smc76._R19A_C_LOCALE + "apt list --upgradable 2>/dev/null"],
      repr((_osu_local76, _osu_remote76, _osu_cmds76)))

_sudo_log76 = _os76.path.join(_TMP76, "sudo.log")
_inst_fail76 = []
with _patched():
    _arm76()
    _patch(_smc76, "run_command", _bash_on76)
    _patch(_ms76, "time", NS(sleep=lambda _s: None, time=_ms76.time.time))
    _inst_ok76 = _ms76._install_linuxgsm(
        NS(short_name="p76new", game_type="csgo", lgsm_name="csgoserver", p=lambda *a, **k: None,
           fail=lambda *a, **k: _inst_fail76.append(a)), NS(id=-76, name="p76"))
with open(_sudo_log76, encoding="utf-8") as _fh76:
    _sudo_calls76 = _fh76.read().splitlines()
_os76.remove(_sudo_log76)
check("install: on a German host the account switch that sudo cannot resolve yet is retried "
      "(sudo's translated `Unbekannter Benutzer` did not match, so the install failed at once)",
      _inst_ok76 is True and len(_sudo_calls76) == 2 and _inst_fail76 == [],
      repr((_inst_ok76, _sudo_calls76, _inst_fail76)))

# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. A failed install the reconciler finds installed
# ════════════════════════════════════════════════════════════════════════════════════════════════
_rc_sid76 = _p9_new_server(P9_HOST, "p76rc", "csgo", 27976, installed=False, status="failed")
try:
    _p9_set(_rc_sid76, install_error="Step 4: p76 failed", install_error_i18n='{"t": "x"}',
            install_retryable=False)
    with _patched():
        _arm76()
        _patch(_sh76, "_looks_installed", lambda app, remote, short, lgsm: True)
        _patch(_sh76, "_notify_servers_changed", lambda app: None)
        _patch(_app76, "still_held", lambda gs: True)
        _patch(_app76, "_install_changed_during_check", lambda gs, before: False)
        with _p9.app_context():
            _app76._reconcile_checked_install(_p9, _app76.db.session.get(_app76.GameServer, _rc_sid76))
    _rc76 = _p9_row(_rc_sid76)
finally:
    _p9_delete_server(_rc_sid76)
check("reconcile: a failed install found installed is marked installed AND sheds the old failure "
      "reason, as InstallJob.finish does (the debug report and a later banner showed it)",
      _rc76.installed is True and _rc76.status == "offline" and _rc76.install_error == ""
      and _rc76.install_error_i18n is None and _rc76.install_retryable is True,
      repr((_rc76.installed, _rc76.status, _rc76.install_error, _rc76.install_error_i18n,
            _rc76.install_retryable)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. A custom-command template holding DEL
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _cc_form76(template):
    with _p9.test_request_context("/c", method="POST", data={
            "name": "P76", "command_template": template, "scope": "all|"}):
        return _app76._custom_cmd_form()


_cc_del76, _cc_ok76 = _cc_form76("say hi\x7f"), _cc_form76("say hi")
check("custom command: a template holding DEL (0x7f) is refused at save, as the run refuses it "
      "(it saved, then answered 400 on every press); a plain one still saves",
      _cc_del76[0] is None and "control characters" in (_cc_del76[1] or "")
      and _cc_ok76[1] is None and _smc76.console_has_control("say hi\x7f"), repr((_cc_del76, _cc_ok76)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. A reboot row held by a LinuxGSM command in flight
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _held76(ticks):
    """_act over one panel-owned row; `ticks` is [(now, safe_start's (outcome, detail))]."""
    gs = NS(id=-76, lgsm_name="p76srv", short_name="p76", name="p76")
    d = {"restore": "pending", "owner": "panel", "stop": "stopped"}
    finished = []
    with _patched():
        _arm76()
        _patch(_hr76, "_scope_ready", lambda remote, row, now: True)
        _patch(_hr76, "_set_rr", lambda g, row: None)
        _patch(_hr76, "_finish", lambda remote, recs, now, rb: finished.append(now))
        with _p9.app_context():
            for now, said in ticks:
                _patch(_hr76, "safe_start", lambda remote, g, _s=said: _s)
                _hr76._act(NS(id=-76), [(gs, d)], now, False)
    return d, finished


_DAY76 = _rw76.INFLIGHT_GIVE_UP
_W76, _I76, _S76 = ("wait", "window"), ("wait", "inflight"), ("wait", "the host did not answer")
# The restore worker's real stream: a tick every ~15 s, one in the out-of-window span about once a
# minute, now and then a host that did not answer — and the same command still in flight a day on.
# Thinned to a tick every ten minutes (each "inflight" one pauses the hour's clock, as it does live).
_stream76 = [(t, (_I76, _W76, _S76)[i % 3]) for i, t in enumerate(range(1000, 1000 + _DAY76, 600))]
_stream76.append((1000 + _DAY76, _I76))
_stuck76 = _held76(_stream76)
_reset76 = _held76([(1000, _I76), (2000, ("failed", "p76 exit 1")), (1000 + _DAY76, _I76)])
check("reboot: a LinuxGSM command in flight fails its row a day on even with out-of-window and "
      "unanswered ticks in between (each one restarted the day, so it held the plan for ever)",
      _stuck76[0]["restore"] == "failed" and "LinuxGSM command" in _stuck76[0]["result"]
      and _stuck76[1] == [1000 + _DAY76], repr(_stuck76))
check("reboot: ...while a start that went ahead (here, an attempt that failed) ends that wait, so "
      "a later in-flight command starts a day of its own",
      _reset76[0]["restore"] == "pending" and _reset76[0].get("inflight_since") == 1000 + _DAY76
      and _reset76[0].get("attempts") == 1 and _reset76[1] == [], repr(_reset76))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. The login-link Tailscale join's forwarding drop-in
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _ts_link76(write_rc):
    writes, warned = [], []
    with _patched():
        _arm76()
        _patch(_smc76, "write_root_file",
               lambda server, name, body, timeout=15: writes.append((name, body)) or ("", "nope", write_rc))
        _patch(_smc76, "run_privileged",
               lambda server, verb, args=(), **k: ("https://login.tailscale.com/a/p76abc", "", 0)
               if verb == "tailscale-up-login" else ("", "", 0))
        _patch(_smc76._log, "warning", lambda msg, *a, **k: warned.append(msg % a))
        res = _smh76.remote_tailscale_up_url(NS(id=-76, name="p76"), advertise_routes="fd00:1::/64")
    return res, writes, warned


_ts_ok76, _ts_bad76 = _ts_link76(0), _ts_link76(1)
check("tailscale link join: the forwarding drop-in carries IPv6 too, the same body the auth-key "
      "join writes (an IPv6 route advertised this way carried nothing, and a re-run dropped a "
      "key-joined host's IPv6 forwarding)",
      _ts_ok76[1] == [("sysctl-tailscale", _smh76._R19A_TS_FORWARDING)]
      and "net.ipv6.conf.all.forwarding = 1" in _smh76._R19A_TS_FORWARDING and not _ts_ok76[2],
      repr(_ts_ok76))
check("tailscale link join: ...and a write that failed is logged, not passed over in silence",
      len(_ts_bad76[2]) == 1 and "NOT enabled" in _ts_bad76[2][0] and _ts_bad76[0][0] is True,
      repr(_ts_bad76))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. Background crontab rewrites ask what every cron write asks
# ════════════════════════════════════════════════════════════════════════════════════════════════
_cp_sid76 = _p9_new_server(P9_HOST, "p76cron", "csgo", 27977)
_cp_upgraded76, _gp_upgraded76 = [], []
try:
    with _patched():
        _arm76()
        _patch(_app76, "ensure_node_tools_cron", lambda r: None)
        _patch(_sh76, "game_account_write_refusal",
               lambda remote, user, **k: _i18n76.Sentence("refused") if user == "p76cron" else None)
        _patch(_smcron76, "upgrade_managed_cron_tracking",
               lambda remote, short, lgsm, **k: _cp_upgraded76.append(short) or False)
        _app76._node_tools_cron_pass(_p9)
        _patch(_smcron76, "upgrade_managed_cron_tracking",
               lambda remote, short, lgsm, **k: _gp_upgraded76.append(short) or True)
        _gp_refused76 = _gp76._cron_follows(NS(id=-76), NS(short_name="p76cron", lgsm_name="p76cron",
                                                          game_type="csgo", query_type=None), 27978)
        _gp_allowed76 = _gp76._cron_follows(NS(id=-76), NS(short_name="p76ok", lgsm_name="p76ok",
                                                          game_type="csgo", query_type=None), 27978)
finally:
    _p9_delete_server(_cp_sid76)
check("cron: the daily node-tools pass does not rewrite the crontab of an account refused for "
      "writes (the host's sudo login), as the Scheduled Tasks page's own upgrade does not; others "
      "it still upgrades",
      "p76cron" not in _cp_upgraded76 and len(_cp_upgraded76) >= 1, repr(_cp_upgraded76))
# The refused one now says so in its audit note (review 1013a) rather than returning "".
check("cron: ...nor does the port resync's re-point, which still re-points a cleared account",
      _gp_upgraded76 == ["p76ok"] and "was not pointed at port 27978 (refused)" in _gp_refused76
      and "27978" in _gp_allowed76,
      repr((_gp_upgraded76, _gp_refused76, _gp_allowed76)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 7. A failed fail2ban reload on the panel host
# ════════════════════════════════════════════════════════════════════════════════════════════════
_f2b_file76 = _os76.path.join(_TMP76, "panel-whitelist.local")
_reloads76 = []


def _write76(path, body):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    return "", "", 0


with _patched():
    _arm76()
    _patch(_so76, "panel_fail2ban_status", lambda: {"installed": True})
    _patch(_so76, "_F2B_PANEL_WHITELIST", _f2b_file76)
    _patch(_so76, "_write_root_file", _write76)
    _patch(_so76, "_run_verb", lambda verb, args, timeout=0: _reloads76.append(verb) or ("", "", 1 if len(_reloads76) == 1 else 0))
    _f2b_first76 = _so76.ensure_panel_host_whitelist(["203.0.113.76"])
    _f2b_again76 = _so76.ensure_panel_host_whitelist(["203.0.113.76"])
    _f2b_third76 = _so76.ensure_panel_host_whitelist(["203.0.113.76"])
check("fail2ban (panel host): a reload that failed is tried again by the next call, not answered "
      "'already applied' because the file it wrote already says the right thing; once it took, "
      "a repeat call does nothing",
      _f2b_first76[0] is False and _f2b_again76 == (True, "fail2ban whitelist applied to every jail")
      and _f2b_third76[1] == "fail2ban whitelist already applied to every jail" and len(_reloads76) == 2,
      repr((_f2b_first76, _f2b_again76, _f2b_third76, _reloads76)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 8. A failed paramiko exec, and an infinite port row
# ════════════════════════════════════════════════════════════════════════════════════════════════
class _Chan76:
    closed = 0

    def close(self):
        _Chan76.closed += 1


class _Stdin76:
    channel = _Chan76()

    def write(self, _text):
        raise OSError("p76 channel write failed")


class _Client76:
    def exec_command(self, command, timeout=None):
        return _Stdin76(), NS(channel=_Chan76()), NS(channel=_Chan76())


with _patched():
    _arm76()
    _patch(_smc76, "get_connection", lambda server: _Client76())
    try:
        _smc76._run_via_paramiko(NS(id=-76, sudo_enabled=False), "true", 10, False, "p76 secret")
        _px76 = None
    except ConnectionError as exc:
        _px76 = exc
check("ssh: an exec whose stdin write fails closes its channel (it stayed open on the pooled "
      "transport, holding one of sshd's sessions) and still raises ConnectionError",
      isinstance(_px76, ConnectionError) and _Chan76.closed == 1, repr((_px76, _Chan76.closed)))

_INF76 = float("inf")
_inf_seen76 = []
with _patched():
    _arm76()
    _patch(_smc76, "run_command", lambda server, cmd, **k: _inf_seen76.append(cmd) or ("", "", 0))
    _patch(_smg76, "_gamedig_player_list", lambda *a: "p76-fallback")
    try:
        _smc76.server_live_metrics(NS(id=-76), "p76", _INF76, force=True)
        _smcron76._remember_map(NS(id=-76), _INF76, "de_dust2")
        _inf_batch76 = _smcron76._batch_queries([(1, "csgo", _INF76, None)])
        _inf_list76 = _smg76._gamedig_player_list_shared(NS(id=-76), "p76", "csgo", _INF76, "p76type")
        _inf_err76 = None
    except OverflowError as exc:
        _inf_err76 = exc
check("ports: a REAL-infinity port row is 'no port' to the live sampler, the map cache, the batch "
      "query and the shared player list (int() raised OverflowError past their ValueError catch)",
      _inf_err76 is None and _inf_batch76 == [] and _inf_list76 == "p76-fallback"
      and _inf_seen76 and "PORT" not in _inf_seen76[0], repr((_inf_err76, _inf_seen76[:1])))

_shutil76.rmtree(_TMP76, ignore_errors=True)

check("part76: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP76_START, repr(_P9_TRIPPED[_TRIP76_START:][:6]))
