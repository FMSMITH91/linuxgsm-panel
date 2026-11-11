"""Scheduled restart, stop or update that warns the players first (the Schedule tab's step chains).

A chain is ONE crontab line whose command the panel composes from a fixed shape:

    cd /home/<u> && ./<s> send '<verb> <message>' ; sleep <secs> ; ... ; ./<s> <action>

* `send` is LinuxGSM's command_send.sh: it types its one argument into the server console's tmux
  session (`tmux send-keys -l`, so literally) and is offered only where the game's config sets
  consoleinteract="yes" (core_getopt.sh) — every game in _SCH_VERBS does.
* The verb is the console's own chat command, from the fixed table below; a game not in it gets no
  chain (the form hides the option and the routes refuse it).
* Every message is shell-quoted with shlex.quote as part of ONE argument, and the action comes from a
  fixed tuple; nothing the viewer typed reaches the line unquoted. The caller sends the result through
  cron._wrap_cron_command, whose base64 recorder means cron and the shell never see the text raw.
* The schedule fires at the START of the chain: the first warning goes out at the scheduled time and
  the action runs that many minutes later. Nothing is shifted.

The job list recognises a chain by parsing it back and composing it again: only a command that comes
out byte-identical is shown as a chain, so a line edited by hand on the host stays raw text.
"""
import re
import shlex

ACTIONS = ("restart", "stop", "update")
MAX_STEPS = 5
MAX_MINUTES = 60
MAX_TEXT = 120

# The console chat command per moderation engine (ssh_manager.game_engine). All three consoles take
# `say <text>`: Source and GoldSrc, idTech3 (Quake 3, CoD, Jedi Knight, ET) and Minecraft Java and
# Bedrock. The same families the console's quick commands offer `say` for.
_SCH_VERBS = {"valve": "say", "idtech3": "say", "minecraft": "say"}

# The names the composed line carries outside quotes. Both come from the server's row, never from the
# request, and are checked by the panel when the row is made; held to this again so a row that is not
# can never put a shell character into the line.
_SCH_IDENT_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*\Z")

NOT_SUPPORTED = "This game's console has no chat command the panel knows, so it can't warn players."
BAD_ACTION = "Warnings can only come before a restart, a stop or an update."
NO_STEPS = "Add at least one warning, or turn off Warn players first."
TOO_MANY = "At most 5 warnings."
BAD_MINUTES = "Each warning is 1 to 60 minutes before the action."
NOT_DECREASING = "Each warning must come later than the one before it (fewer minutes before the action)."
BAD_TEXT = "Each warning needs a message of 1 to 120 characters."
CONTROL_TEXT = "A warning can't contain line breaks, tabs or other control characters."
SEMICOLON_TEXT = "A warning can't contain ; (game consoles read it as the start of another command)."


def say_verb(game_type):
    """The console's chat command for `game_type`, or "" when the panel knows none."""
    from panel.ops.ssh_manager.game import game_engine
    if (game_type or "").lower() == "mcb":
        return "say"
    return _sch_engine_verb(game_engine(game_type))


def _sch_engine_verb(engine):
    """The chat command for a moderation engine family (keyed by family, not by game)."""
    return _SCH_VERBS.get(engine, "")


def _sch_minutes(value):
    """An int of minutes from JSON (a number or a digit string), or None. A bool is not a number."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdecimal() and value.strip().isascii():
        return int(value.strip())
    return None


def _sch_text_refusal(text):
    """Why `text` (already stripped) can't be a warning, or None."""
    if not text or len(text) > MAX_TEXT:
        return BAD_TEXT
    if not text.isprintable():
        return CONTROL_TEXT
    if ";" in text:
        return SEMICOLON_TEXT
    return None


def _sch_step(item):
    """((minutes, message), None) for one warning from the request, or (None, refusal)."""
    if not isinstance(item, dict):
        return None, BAD_MINUTES
    mins = _sch_minutes(item.get("minutes"))
    if mins is None or not 1 <= mins <= MAX_MINUTES:
        return None, BAD_MINUTES
    text = item.get("message")
    text = text.strip() if isinstance(text, str) else ""
    why = _sch_text_refusal(text)
    return (None, why) if why else ((mins, text), None)


def check(action, warnings):
    """(steps, None) — steps a list of (minutes, message), latest-first order — or (None, refusal).

    `warnings` is the request's list of {minutes, message}: 1 to MAX_STEPS of them, minutes 1-60 and
    strictly decreasing (so the whole chain is at most 60 minutes), each message 1-120 printable
    characters without `;`.
    """
    if action not in ACTIONS:
        return None, BAD_ACTION
    if not isinstance(warnings, list) or not warnings:
        return None, NO_STEPS
    if len(warnings) > MAX_STEPS:
        return None, TOO_MANY
    steps = []
    for item in warnings:
        step, why = _sch_step(item)
        if why:
            return None, why
        if steps and step[0] >= steps[-1][0]:
            return None, NOT_DECREASING
        steps.append(step)
    return steps, None


def compose(user, selfname, verb, action, steps):
    """The chain's shell command (see the module docstring), or None for names it can't carry.

    `;` between the steps, never `&&`: a send that fails — the server already stopped, the console
    busy — must not stop the restart, stop or update it was warning about. The `&&` after `cd` only
    joins the cd to the first send; cron starts the job in the account's home anyway.
    """
    if not (_SCH_IDENT_RE.match(user or "") and _SCH_IDENT_RE.match(selfname or "")):
        return None
    if action not in ACTIONS or verb not in _SCH_VERBS.values():
        return None
    parts = []
    for i, (mins, text) in enumerate(steps):
        after = steps[i + 1][0] if i + 1 < len(steps) else 0
        parts.append("./%s send %s" % (selfname, shlex.quote("%s %s" % (verb, text))))
        parts.append("sleep %d" % ((mins - after) * 60))
    parts.append("./%s %s" % (selfname, action))
    return "cd /home/%s && %s" % (user, " ; ".join(parts))


def _sch_sends(toks, selfname, verb):
    """[(message, seconds)] from the tokens after `cd /home/<u> &&`, and the tokens left, or None."""
    found, prefix = [], verb + " "
    while len(toks) >= 7 and toks[:2] == ["./" + selfname, "send"]:
        said, semi1, sleep, secs, semi2 = toks[2:7]
        if (semi1, sleep, semi2) != (";", "sleep", ";") or not said.startswith(prefix) or not secs.isdecimal():
            return None, toks
        found.append((said[len(prefix):], int(secs)))
        toks = toks[7:]
    return found, toks


def parse(command, user, selfname, verb):
    """{"action", "steps": [{"minutes", "message"}]} for a command compose() wrote, else None."""
    if not verb or not command:
        return None
    try:
        toks = shlex.split(command)
    except ValueError:
        return None
    if toks[:3] != ["cd", "/home/%s" % user, "&&"]:
        return None
    sends, rest = _sch_sends(toks[3:], selfname, verb)
    if not sends or len(rest) != 2 or rest[0] != "./" + selfname:
        return None
    mins, steps = 0, []
    for text, secs in reversed(sends):
        if secs % 60:
            return None
        mins += secs // 60
        steps.insert(0, {"minutes": mins, "message": text})
    good, why = check(rest[1], steps)
    if why or compose(user, selfname, verb, rest[1], good) != command:
        return None
    return {"action": rest[1], "steps": steps}


def audit_detail(schedule, action, steps):
    """The audit row's detail: the schedule, the action and every warning as it was saved."""
    said = "; ".join("%d min %r" % (m, t) for m, t in steps)
    return "%s %s, warnings: %s" % (schedule, action, said)


def from_request(gs, chain):
    """(command, detail_tail, None) for the request's `chain` on server `gs`, or (None, None, refusal)."""
    verb = say_verb(gs.game_type)
    if not verb:
        return None, None, NOT_SUPPORTED
    if not isinstance(chain, dict):
        return None, None, NO_STEPS
    action = chain.get("action")
    steps, why = check(action if isinstance(action, str) else "", chain.get("warnings"))
    if why:
        return None, None, why
    command = compose(gs.short_name, gs.lgsm_name or gs.short_name, verb, action, steps)
    if command is None:
        return None, None, NOT_SUPPORTED
    return command, (action, steps), None
