"""Whether a game server's console is attached, stood in for a host command. Not a test part.

The file browser refuses the live console's log, `log/console` and `log` only while the server's
console is attached (files._console_guard), and it asks the console's own question for that:
a live `<selfname>` session on one of the account's `<selfname>-*` tmux sockets in
/tmp/tmux-<uid> (_core._tmux_live_socket_sh). A part that runs the guard in a real bash rewrites
the command with as_state(): the tmux folder becomes one of this module's own, and `tmux` a shell
function answering for that state. Nothing here starts tmux or reads the real /tmp/tmux-<uid>.

    live     a `<selfname>-p` socket whose session answers has-session (pipe-pane is writing)
    stopped  the folder exists, no socket: nothing is attached (LinuxGSM has not started it)
    stale    a `<selfname>-p` socket left by an earlier start, whose server is gone
    unread   a FILE where the folder is: it cannot be listed, so the state cannot be read
"""
import os
import tempfile

_TMUX_D = "D=/tmp/tmux-$(id -u)"  # nosec B108 - the text replaced, not a path used
_ANSWERS = {"live": 'tmux() { [ "$1" = -L ] && [ "$3" = has-session ]; }; ',
            "stale": "tmux() { return 1; }; ",
            "stopped": "tmux() { return 1; }; ",
            "unread": "tmux() { return 1; }; "}
STATES = tuple(_ANSWERS)
_ROOT = {}


def _root():
    if "d" not in _ROOT:
        _ROOT["d"] = tempfile.mkdtemp(prefix="lgsm-unit-console-")
    return _ROOT["d"]


def _folder(state, selfname):
    d = os.path.join(_root(), "%s-%s" % (state, selfname))
    if state == "unread":
        if not os.path.exists(d):
            with open(d, "w", encoding="utf-8"):
                pass
        return d
    os.makedirs(d, exist_ok=True)
    if state in ("live", "stale"):
        with open(os.path.join(d, selfname + "-p"), "a", encoding="utf-8"):
            pass
    return d


def as_state(sh, state, selfname):
    """`sh` (a host command) run as if `selfname`'s console were in `state` (see the module doc)."""
    if _TMUX_D not in sh:
        return sh
    return _ANSWERS[state] + sh.replace(_TMUX_D, "D=" + _folder(state, selfname))
