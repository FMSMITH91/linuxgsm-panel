"""Part 268 of the unit suite: review pass 33's security fixes in world reset and the root cron page.

1. World reset's start parameters are bounded: past what a server can be started with (131,072
   characters, before or after the settings are put in) they are refused, and building them stops at
   that size, so a long setting named many times costs linear time, not references x length.
2. A value of only `--port` / `++ port` counts as possibly setting port (another line's arithmetic
   would decrement or increment it), and so does bash 5.3's `${ cmd; }` / `${| cmd; }`, which runs in
   the config's own shell.
3. Root cron: a command typed with `\\%` (the crontab way) is stored so that cron runs it whole and the
   page shows what cron runs; two backslashes in a row (which Debian's and cronie's cron read
   differently) are refused; a job holding them, or a bare `%` feeding it standard input, is shown
   with a note and offers Delete only.

HOW IT RUNS. The world reset reads run in-process over config texts (part203's Valheim fixture), with
lgsm_cfg_texts stubbed for vh_plan; bash itself confirms what the arithmetic and `${ cmd; }` forms set.
The root cron routes run on part12's app with part239's stand-ins and its transport tripwire armed.
Cron's own reading of a command is checked against a transcription of both crons' do_command.c loops.
"""
import re
import subprocess as _sp268  # nosec B404 - bash over fixed snippets of this part's own
import time as _time268
import types as _types268

from unit.part01 import check, eq, skip
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9_arm, _p9_audit, _p9_client, _p9_patch_sm,
                         _p9_restore_all)
from unit.part203 import _vh203
from unit.part239 import _GOOD239, _set_on239, _sha239, _stubs239
from panel.services import root_cron as _rc268
from panel.services import world_reset as _wwr268

_trips268 = len(_P9_TRIPPED)


def _try268(fn, *args):
    """Run `fn(*args)`; on an error, ("raised", its type name), so a mutation that crashes fails by name."""
    try:
        return fn(*args)
    except Exception as e:  # noqa: BLE001 - reported as a value, so the check names the failure
        return ("raised", type(e).__name__)


def _bash268(script):
    """What bash prints for `script` (stdout, stripped)."""
    out = _sp268.run(["bash", "-c", script], capture_output=True, text=True, timeout=20,  # nosec B603 B607 - fixed
                     check=False)
    return out.stdout.strip()


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. World reset: the start parameters are bounded, and building them is linear
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _words268(texts):
    """Start_words over `texts` for account p268u, server p268srv."""
    return _try268(_wwr268.start_words, texts, "p268u", "p268srv")


def _repeat268(value_len, refs):
    """Config texts whose startparameters name one setting of `value_len` characters `refs` times."""
    return ['a0="%s"\nstartparameters="%s"\n' % ("x" * value_len, " ".join(["${a0}"] * refs)), "", "", "", ""]


def _start_seconds268(n):
    """The fastest of three start_words runs over a setting of `n` characters named `n` times."""
    texts = _repeat268(n, n)
    best = None
    for _ in range(3):
        t0 = _time268.perf_counter()
        _words268(texts)
        took = _time268.perf_counter() - t0
        best = took if best is None else min(best, took)
    return best


# Quadruple both: the config grows four-fold, the text it expanded to sixteen-fold. Measured before the fix:
# 800 -> 3,200 took 0.12 s -> 2 s (a 10 MB string built and then split); now both stop at the bound.
_rs_small268, _rs_big268 = _start_seconds268(800), _start_seconds268(3200)
check("world reset r33: start_words over a config 4x as large (a setting 4x as long named 4x as often) takes under "
      "8x as long (building stops at the bound, so the work follows the config, not references x length)",
      _rs_big268 < 8 * _rs_small268 + 0.05, "800: %.3f s, 3200: %.3f s" % (_rs_small268, _rs_big268))

_TOO_LONG268 = "the start parameters, with the settings they name put in, are longer than a server can be started with"
_under268 = _words268(_repeat268(1000, 100))
eq("world reset r33: a setting put in many times is still read while the start string fits (100 x 1,000 "
   "characters: 100 words), and refused once it does not (132 x 1,000), with the reason",
   (len(_under268[0] or []), _under268[1], _words268(_repeat268(1000, 132))),
   (100, None, (None, _TOO_LONG268)))
# 131,072 is Linux's MAX_ARG_STRLEN: LinuxGSM hands the start string to tmux as one argument. The raw text is
# startparameters + " " + extraparams, so 131,071 characters of startparameters is exactly the limit.
eq("world reset r33: the bound is 131,072 characters: start parameters of exactly that length are read, one "
   "more is refused",
   [(_words268(['startparameters="%s"\n' % ("x" * n), "", "", "", ""])[0] or [""])[0] == "x" * n
    for n in (131071, 131072)],
   [True, False])
eq("world reset r33: start parameters longer than the bound are refused before anything is expanded, even "
   "when the settings they name are empty (30,000 references to an empty setting)",
   _words268(['a0=""\nstartparameters="%s"\n' % ("${a0} " * 30000), "", "", "", ""]),
   (None, _TOO_LONG268))
eq("world reset r33: a setting whose own expansion passes the bound ($HOME 15,000 times) is refused too",
   _words268(['a0="%s"\nstartparameters="-x ${a0}"\n' % ("$HOME" * 15000), "", "", "", ""]),
   (None, _TOO_LONG268))


def _vh_plan268(inst):
    """Valheim's plan over part203's config with `inst` as the instance file, lgsm_cfg_texts stubbed."""
    _p9_arm(who="part268")
    _p9_patch_sm("lgsm_cfg_texts", lambda server, user, selfname, read_only=False: _vh203(inst))
    try:
        return _try268(_wwr268.vh_plan, _types268.SimpleNamespace(remote=None, short_name="vhserver",
                                                                  lgsm_name="vhserver"))
    finally:
        _p9_restore_all()


_vh_ok268 = _vh_plan268("")
eq("world reset r33 (the caller): Valheim's plan is refused for a start line naming a long setting many times, "
   "and still made for LinuxGSM's own config",
   (_vh_plan268('servername="%s"\nstartparameters="%s"\n' % ("x" * 2000, "${servername} " * 100)),
    _vh_ok268[1], bool(_vh_ok268[0])),
   ((None, _TOO_LONG268), None, True))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. A bare `--key` / `++key`, and bash 5.3's `${ cmd; }`, may set a key
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _port268(value):
    """What cfg_values reads for port beside another key's line holding `value`: the value, or None."""
    got = _try268(_wwr268.cfg_values, ['port="5"\nother="%s"\n' % value], ["port"])
    return got[0]["port"] if got[0] else got[0]


eq("world reset r33: bash's arithmetic decrements or increments port through another key's value of only "
   "--port, -- port or ++port (bash itself)",
   [_bash268('port=5; other="%s"; : $((other)); echo $port' % v) for v in ("--port", "-- port", "++port")],
   ["4", "4", "6"])
eq("world reset r33: so a value of only --port, ++port, -- port or ++<tab>port counts as possibly setting it, "
   "and port is not read from that config",
   [_port268(v) for v in ("--port", "++port", "-- port", "++\tport", "x --port y")], [None] * 5)
eq("world reset r33: ...while a value that only names it still reads (-port, - -port, --porter, port-)",
   [_port268(v) for v in ("-port", "- -port", "--porter", "port-", "a-port ${port}")], ["5"] * 5)
eq("world reset r33 (the caller): Valheim's plan is refused when another line can decrement the port it starts "
   "with",
   _vh_plan268('other="--port"\nfoo="$((other))"\n')[0], None)

_FUNSUB268 = ("${ printf -v port %s 2; }", "${| printf -v port %s 3; }", "${\tprintf -v port %s 7; }")
_bash_ver268 = _bash268('echo "${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}"')
if re.fullmatch(r"\d+\.\d+", _bash_ver268) and tuple(int(p) for p in _bash_ver268.split(".")) >= (5, 3):
    eq("world reset r33: bash 5.3's ${ cmd; } and ${| cmd; } run in the current shell and set port from another "
       "key's value (bash itself)",
       [_bash268("port=5; x=\"%s\"; echo $port" % v) for v in _FUNSUB268], ["2", "3", "7"])
else:
    skip("world reset r33: bash 5.3's ${ cmd; } and ${| cmd; } run in the current shell and set port from "
         "another key's value (bash itself)", "this bash is %s, older than 5.3" % _bash_ver268)
eq("world reset r33: so a value holding ${ , ${<tab> or ${| counts as possibly setting any key",
   [_port268(v) for v in _FUNSUB268], [None] * 3)
eq("world reset r33: ...while ${port}, ${port:-1} and a $(…) command substitution (a subshell) still read",
   [_port268(v) for v in ("${port}", "${port:-1}", "$(printf -v port %s 2)")], ["5"] * 3)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. Root cron: `\%` runs whole, and the page shows what cron runs
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _cron268(cmd, debian):
    r"""Cron's reading of a job's command text, (command, standard input or None): do_command.c, both loops.

    Debian's and Ubuntu's cron (3.0pl1) also turns `\\` into `\`; cronie keeps both.
    """
    out, esc = [], False
    for i, ch in enumerate(cmd):
        if esc:
            esc = False
            if ch == "%" or (debian and ch == "\\"):
                out[-1] = ch
            else:
                out.append(ch)
        elif ch == "%":
            return "".join(out), _cron_input268(cmd[i + 1:])
        else:
            out.append(ch)
            esc = ch == "\\"
    return "".join(out), None


def _cron_input268(rest):
    """What cron writes to the command's standard input from the text after the cut (do_command.c's second loop)."""
    fed, esc = [], False
    for ch in rest:
        if esc and ch != "%":
            fed.append("\\")
        if not esc and ch == "%":
            ch = "\n"
        esc = ch == "\\"
        if not esc:
            fed.append(ch)
    return "".join(fed) + ("\\" if esc else "")


_TYPED268 = ("date +%F", "date +\\%F", "tar czf /root/b-\\%F.tgz /etc", "a%b\\%c%", "x\\y \\;", "end\\",
             "printf 'x\\n'")
_runs268 = []
for _t268 in _TYPED268:
    _line268 = _rc268.job_line("30 4 * * *", _t268)[0] or "30 4 * * * "
    _cmd268 = _line268[len("30 4 * * * "):]
    _row268 = _rc268.rows(_line268 + "\n")[0]
    _runs268.append((_cron268(_cmd268, True), _cron268(_cmd268, False), _row268["command"], _row268["stdin"],
                     _row268["mixed"]))
eq("root cron r33: every typed command runs whole under both crons, as typed with each \\% read as %, and the "
   "page shows exactly that (a % typed after a backslash was stored as \\\\%, which cron cut there)",
   _runs268, [((t.replace("\\%", "%"), None),) * 2 + (t.replace("\\%", "%"), None, False) for t in _TYPED268])
eq("root cron r33: the crons read two backslashes in a row differently (Debian one, cronie two), so a command "
   "holding them is refused with the reason, before % or not",
   (_cron268("echo a\\\\b", True) != _cron268("echo a\\\\b", False),
    _rc268.job_line("@daily", "echo a\\\\b"), _rc268.job_line("@daily", "date +\\\\%F")[0]),
   (True, (None, _rc268.TWO_BACKSLASHES), None))
_hand268 = _rc268.rows("0 1 * * * mail -s hi root%body\\%x%line2\n0 2 * * * echo a\\\\b\n")
eq("root cron r33: a job from a shell feeding its command input with a bare % shows the command cron runs and "
   "that input, as both crons read it; one with two backslashes in a row is marked and shown as written",
   [(r["command"], r["stdin"], r["mixed"]) for r in _hand268]
   + [_cron268("mail -s hi root%body\\%x%line2", d) for d in (True, False)],
   [("mail -s hi root", "body%x\nline2", False), ("echo a\\\\b", None, True)]
   + [("mail -s hi root", "body%x\nline2")] * 2)


def _page268():
    """The root cron page and its change route: what is written, what the page offers."""
    writes = []
    cur = "0 1 * * * mail root%body\n0 2 * * * echo a\\\\b\n0 3 * * * /plain\n"
    _p9_arm(who="part268")
    try:
        _set_on239(True)
        _stubs239(cur, writes=writes)
        a = _p9_client(P9_ADMIN)
        page = a.get("/root-cron/%d" % P9_HOST).get_data(as_text=True)
        base = {"sha": _sha239(cur), "password": _GOOD239, "op": "add", "schedule": "30 4 * * *"}
        a.post("/root-cron/%d/change" % P9_HOST, data=dict(base, command="tar czf /root/b-\\%F.tgz /etc"))
        added = list(writes)
        a.post("/root-cron/%d/change" % P9_HOST, data=dict(base, command="echo a\\\\b"))
        refused = _p9_audit("root_cron_change")
    finally:
        _set_on239(False)
        _p9_restore_all()
    return cur, page, added, writes, refused


_cur268, _pg268, _added268, _writes268, _refused268 = _page268()
eq("root cron r33 (the route): a command typed with \\% is written so cron runs it whole; one with two "
   "backslashes in a row writes nothing and the refusal is audited",
   (_added268, len(_writes268), _refused268.success, _rc268.TWO_BACKSLASHES in _refused268.detail),
   ([(P9_HOST, _cur268 + "30 4 * * * tar czf /root/b-\\%F.tgz /etc\n", _sha239(_cur268))], 1, False, True))
eq("root cron r33 (the page): the job fed input by a bare % shows that input with its note, the one with two "
   "backslashes its note, and only the plain job offers Save (all three Delete)",
   ('class="small text-warning rc-stdin"' in _pg268, ">body</code>" in _pg268,
    'class="small text-warning rc-mixed"' in _pg268, _pg268.count('name="op" value="save"'),
    _pg268.count('name="op" value="delete"')),
   (True, True, True, 1, 3))

check("part268: no check reached a real host", len(_P9_TRIPPED) == _trips268, repr(_P9_TRIPPED[_trips268:][:4]))
