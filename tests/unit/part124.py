r"""Part 124 of the unit suite: the twenty-second review's app-core, installer and helper fixes (review 1022b, A).

* A number past Python's 4300-digit int() limit in a game account's own file no longer raises out of
  the code that reads it: a valve sibling's sourcetvport/clientport (every Install on the host was a
  500), maxplayers/slots (the server's player count read as unknown), a console reply's player count
  (console_player_list promises never to raise).
* The colour console drops NUL/BEL before its `\r` arithmetic, as render_line does.
* install.sh's update path says "System updated" only when the upgrade said so.
* An OS update's keep step: on a remote, a preferences file that could not be fully written is never
  handed to apt (the host's own pins were ignored for that run); on the panel host the host's own
  /etc/apt/preferences is copied byte for byte, and sshd-set-directive writes the rest of
  sshd_config back byte for byte.

HOW IT RUNS. app/monitoring/game/terminal functions directly over stand-ins (part51's sibling harness
for the port walk); install.sh's block and the remote keep shell under bash in this part's temp dir
with stand-in tools first on PATH; the helper in-process (part05's). Nothing reaches apt, a host,
sudo or the checkout's data/.
"""
import io as _io124
import os
import shutil as _shutil124
import subprocess as _sp124  # nosec B404 - bash over this part's own temp dir, fixed argv
import tempfile as _tf124
from types import SimpleNamespace as NS

from unit.part01 import check
from unit.part05 import _helper as _h124, _root
from unit.part12 import _P9_TRIPPED, _p9_arm, _p9_patch, _p9_restore_all
from unit.part20 import _patch, _patched
from unit.part51 import _Q51, _alloc51
from unit.part118 import _DPKG118, _SIM118
from unit.reboot41_a import _POWER_NAMES41
import app as _app124  # noqa: E402
from panel.core import terminal as _term124
from panel.ops.ssh_manager import game as _game124
from panel.security import privileged as _priv124
from panel.services import monitoring as _mon124

_TRIP124_START = len(_P9_TRIPPED)
_TMP124 = _tf124.mkdtemp(prefix="lgsm-unit-p124-")
_HUGE124 = "1" * 5000          # past CPython's default int() digit limit (4300)


def _standin124(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
    os.chmod(path, 0o700)  # nosec B103 - this part's own temp dir


def _bash124(script, env):
    r = _sp124.run(["bash", "-c", script], capture_output=True, text=True, timeout=60,  # nosec B603 B607
                   env=env)
    return r.stdout, r.stderr, r.returncode


def _env124(bin_, **extra):
    return dict({"PATH": bin_ + ":/usr/bin:/bin", "SIM124": _SIM118, "HOME": _TMP124, "LC_ALL": "C.UTF-8"},
                **extra)


# ── 1. an over-long number in a game account's own file ──────────────────────────────────────────
def _sibling_ports124():
    got = _alloc51(lambda remote, user, selfname, keys: {
        "clientport": _HUGE124 if user == "csgo0" else "", "sourcetvport": "27020" if user == "csgo1" else ""})
    check("free-port: a valve sibling whose clientport is past int()'s 4300 digits reserves nothing for it "
          "instead of raising ValueError out of every Install on the host; its other port still steers",
          got == ((27021, True), []), repr(got))
    with _patched():
        _patch(_app124, "_remote_listening_ports", lambda remote: set())
        sib = NS(game_type="csgo", port=27015, short_name="csgo0", lgsm_name="csgoserver")
        _patch(_app124, "GameServer", NS(query=_Q51([sib])))
        _patch(_app124, "sm_game_engine", lambda gt: "valve")
        # The new server's own config and the sibling's: both an over-long clientport, both 27020.
        _patch(_app124, "lgsm_get_values",
               lambda remote, user, selfname, keys: {"clientport": _HUGE124, "sourcetvport": "27020"})
        try:
            aux = _app124._resolve_source_aux_ports(NS(name="h124"), 1, "new", "csgoserver", 27016)
        except Exception as e:  # noqa: BLE001 - the answer under test
            aux = e
    check("aux ports: an over-long clientport (the new server's and a sibling's) is skipped rather than "
          "raising, and the sourcetvport the sibling holds is still moved off",
          aux == {"sourcetvport": "27021"}, repr(aux))


def _max_players124():
    got = {}
    for case, vals in (("maxplayers over-long", {"maxplayers": _HUGE124, "slots": "16"}),
                       ("both over-long", {"maxplayers": _HUGE124, "slots": _HUGE124}),
                       ("control", {"maxplayers": "24", "slots": ""})):
        _p9_patch(_mon124, "lgsm_get_values", lambda *a, _v=vals, **k: _v)
        try:
            got[case] = _mon124._read_max_config(NS(remote=None, short_name="s124", lgsm_name="csgoserver"))
        except Exception as e:  # noqa: BLE001 - the answer under test
            got[case] = type(e).__name__
    check("max players: a maxplayers past int()'s digit limit is no capacity (slots is read next) instead of "
          "a raise that made the whole player count unknown; a real one still reads",
          got == {"maxplayers over-long": (True, 16), "both over-long": (True, None),
                  "control": (True, 24)}, repr(got))


_VALVE124 = ("players : %s humans, 0 bots (24 max)\n"
             "# userid name uniqueid connected ping loss state rate adr\n"
             "#  2 \"Bob\" STEAM_1:0:123 00:10 50 0 active 80000\n")


def _console_counts124():
    got = {}
    for case, eng, out in (("minecraft over-long", "minecraft",
                            "There are %s of a max of 20 players online: Steve\n" % _HUGE124),
                           ("valve over-long", "valve", _VALVE124 % _HUGE124),
                           ("minecraft control", "minecraft", "There are 1 of a max of 20 players online: Steve\n"),
                           ("valve control", "valve", _VALVE124 % "1")):
        try:
            r = _game124._parse_player_reply(eng, out)
            got[case] = None if r is None else [p["name"] for p in r]
        except Exception as e:  # noqa: BLE001 - the answer under test
            got[case] = type(e).__name__
    check("console players: a reply whose own count is past int()'s digit limit is no reply (None) instead "
          "of a ValueError out of console_player_list, which promises never to raise; real replies still parse",
          got == {"minecraft over-long": None, "valve over-long": None,
                  "minecraft control": ["Steve"], "valve control": ["Bob"]}, repr(got))


# ── 2. the colour console drops a C0 byte before the \r arithmetic ────────────────────────────────
def _c0_columns124():
    lines = ("ab\x07cd\rXY", "a\x00\x00bcd\rZ", "x\x07\by", "\x1b[31mab\x07c\x1b[0m\rQ", "tab\there\rT")
    got = {ln: (_term124.strip_escapes(_term124.render_line_colour(ln)) if "\x1b" in ln
                else _term124.render_line_colour(ln), _term124.render_line(ln)) for ln in lines}
    check("console colour: a NUL/BEL in a line takes no column, so a later \\r overwrite or \\b lands where "
          "render_line puts it (it shifted one column right per byte); tabs still take theirs",
          all(a == b for a, b in got.values()), repr(got))


# ── 3. install.sh's update path: "System updated" only when it was ───────────────────────────────
# The block runs to its real `${UPG_SUDO} reboot` branch once game_sessions_running stops answering
# (renamed, or a branch put before it): stand-ins for reboot, sleep and sudo, and reboot41_a's refusing
# power commands first on PATH, as reboot41_a guards the same blocks (review 1022c: only the order of the
# block's branches kept it from the machine's reboot). Each case asserts no reboot was asked for.
_POWER124 = os.path.join(_TMP124, "power-refused")
os.makedirs(_POWER124)
for _pn124 in _POWER_NAMES41:
    _standin124(os.path.join(_POWER124, _pn124), '#!/bin/sh\necho "REFUSED $(basename "$0") $*"\nexit 1\n')


def _install_update124():
    text = open(os.path.join(_root, "install.sh"), encoding="utf-8").read()
    start = text.index('        if [[ "${PANEL_NO_UPGRADE:-0}" != "1" ]] && command -v apt-get')
    block = text[start:text.index("\n        exit 0\n", start)]
    flag = os.path.join(_TMP124, "reboot-required")
    got = {}
    for case, rc_up, pending in (("refused", "100", False), ("ok", "0", False),
                                 ("refused, reboot pending", "100", True)):
        if pending:
            open(flag, "w", encoding="utf-8").close()
        elif os.path.exists(flag):
            os.unlink(flag)
        out, err, rc = _bash124(
            "set -euo pipefail\ninfo() { :; }\nwarn() { echo \"WARN $*\"; }\nok() { echo \"OK $*\"; }\n"
            "_r34a_keep_installed() { _R34A_KEEP_OPTS=(); _R34A_KEEP_DIR=''; }\n"
            "_r30a_apt_ni() { shift; case \" $* \" in *' full-upgrade '*) return %s;; esac; return 0; }\n"
            "apt-get() { echo 'Inst tzdata [1] (2 Ubuntu:24.04 [all])'; }\n"
            "game_sessions_running() { return 0; }\n"
            "reboot() { echo REBOOTING; }\nsleep() { :; }\nsudo() { echo \"REFUSED sudo $*\"; return 1; }\n"
            "command() { return 0; }\nid() { echo 0; }\n%s\n"
            % (rc_up, block.replace("/var/run/reboot-required", flag)),
            _env124(_POWER124 + ":" + _TMP124, PANEL_NO_UPGRADE="0"))
        got[case] = (rc, "OK System updated" in out, "WARN The OS was not fully updated" in out,
                     "WARN The update needs a reboot" in out, "REBOOTING" in out or "REFUSED" in out, err[-200:])
    check("install.sh: an update whose OS upgrade was refused says the OS was not fully updated, not "
          "'System updated — no reboot required'; a pending reboot is still said, and a good run unchanged "
          "(no case reaches a reboot)",
          {k: v[:5] for k, v in got.items()}
          == {"refused": (0, False, True, False, False), "ok": (0, True, False, False, False),
              "refused, reboot pending": (0, False, False, True, False)}, repr(got))


# ── 4. the remote keep: a preferences file not fully written is never used ───────────────────────
def _remote_keep124():
    got = {}
    for case in ("cat fails", "file cannot be created", "control"):
        d = os.path.join(_TMP124, "keep-" + case.replace(" ", "-"))
        kd = os.path.join(d, "kd")
        os.makedirs(kd)
        _standin124(os.path.join(d, "apt-get"), "#!/bin/bash\nprintf '%s' \"$SIM124\"\n")
        _standin124(os.path.join(d, "dpkg"), _DPKG118)
        _standin124(os.path.join(d, "mktemp"), "#!/bin/bash\necho %s\n" % kd)
        own = os.path.join(d, "own-preferences")
        with open(own, "w", encoding="utf-8") as fh:
            fh.write("Package: *\nPin: release o=Blocked\nPin-Priority: -1\n")
        if case == "cat fails":
            _standin124(os.path.join(d, "cat"), "#!/bin/bash\nexit 1\n")
        if case == "file cannot be created":
            os.makedirs(os.path.join(kd, "preferences"))     # a directory: no write, root or not
        out, err, rc = _bash124(_priv124._R34A_KEEP_SH.replace("/etc/apt/preferences", own)
                                + _priv124._R34J_KEEP_SKIPPED + "; echo \"PO<$po> KEPT<$kept>\"\n", _env124(d))
        got[case] = (rc == 0 and "Dir::Etc::Preferences" in out, "KEPT<>" in out,
                     "Could not check for packages apt would downgrade (its preferences file could not be "
                     "written)" in out, out[-300:], err[-200:])
    check("remote OS update: a keep file the host's own preferences could not be copied into (or that could "
          "not be written) is never handed to apt, and the log says why (apt ran with the operator's pins "
          "ignored); a keep that was written is still used",
          {k: v[:3] for k, v in got.items()}
          == {"cat fails": (False, True, True), "file cannot be created": (False, True, True),
              "control": (True, False, False)}, repr(got))


# ── 5. the helper copies the operator's files byte for byte ──────────────────────────────────────
_LATIN124 = b"Package: *\nPin: release l=D\xe9p\xf4t\nPin-Priority: -1\n"


def _helper_prefs_bytes124():
    d = os.path.join(_TMP124, "helper-prefs")
    os.makedirs(d)
    _standin124(os.path.join(d, "apt-get"), "#!/bin/bash\nprintf '%s' \"$SIM124\"\n")
    _standin124(os.path.join(d, "dpkg"), _DPKG118)
    own = os.path.join(d, "own-preferences")
    with open(own, "wb") as fh:
        fh.write(_LATIN124)
    env = dict(_h124._clean_env(), PATH=d + ":/usr/bin:/bin", SIM124=_SIM118)
    _p9_patch(_h124, "_R34A_APT_PREFS", own)
    real = _h124.resolve
    _p9_patch(_h124, "resolve", lambda prog: os.path.join(d, prog) if prog == "dpkg" else real(prog))
    opts = _h124._r33_keep_installed_opts(os.path.join(d, "apt-get"), env, d, _io124.StringIO())
    with open(os.path.join(d, "preferences"), "rb") as fh:
        body = fh.read()
    check("os update (panel host): the host's /etc/apt/preferences is copied into the keep file byte for "
          "byte (a Latin-1 pin became U+FFFD and matched nothing, lifting a -1 block for the run), after the keep",
          len(opts) == 2 and body.endswith(_LATIN124) and body.startswith(b"Package: proftpd-core\n"),
          repr((opts, body[-120:])))


def _sshd_directive_bytes124():
    d = os.path.join(_TMP124, "sshd")
    os.makedirs(d)
    cfg = os.path.join(d, "sshd_config")
    with open(cfg, "wb") as fh:
        fh.write(b"# r\xe9glage du d\xe9p\xf4t\nPort 22\n#ClientAliveInterval 0\n"
                 b"Match User b\xe9a\n  X11Forwarding no\n")
    _p9_patch(_h124, "SSHD_CONFIG", cfg)
    _p9_patch(_h124, "_sshd_includes_dropin_dir", lambda: False)
    _p9_patch(_h124, "_sshd_effective_value", lambda key: "300")
    rc = _h124.do_sshd_set_directive(["ClientAliveInterval", "300"], None)
    with open(cfg, "rb") as fh:
        body = fh.read()
    check("sshd-set-directive: every line it was not asked to change goes back byte for byte (a Latin-1 "
          "comment or Match name was rewritten as U+FFFD); the directive is still set",
          (rc, body) == (0, b"# r\xe9glage du d\xe9p\xf4t\nPort 22\nClientAliveInterval 300\nMatch User b\xe9a\n"
                            b"  X11Forwarding no\n"), repr((rc, body)))


try:
    _p9_arm(who="part124")
    _sibling_ports124()
    _max_players124()
    _console_counts124()
    _c0_columns124()
    _install_update124()
    _remote_keep124()
    _p9_restore_all()
    _p9_arm(who="part124")
    _helper_prefs_bytes124()
    _p9_restore_all()
    _p9_arm(who="part124")
    _sshd_directive_bytes124()
finally:
    _p9_restore_all()
    _shutil124.rmtree(_TMP124, ignore_errors=True)

check("part124: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP124_START, repr(_P9_TRIPPED[_TRIP124_START:][:6]))
