r"""Part 174 of the unit suite: Warn players first on the Schedule tab (panel/services/schedule_chains.py).

Held here:
* Which games get the option: the consoles whose chat command the panel knows (Source/GoldSrc, idTech3,
  Minecraft Java and Bedrock, all `say`), and no other.
* What is checked: an action from restart/stop/update, 1-5 warnings, minutes 1-60 and strictly
  decreasing, each message 1-120 printable characters without `;`.
* The composed line: `cd /home/<u> && ./<s> send '<say text>' ; sleep N ; ... ; ./<s> <action>`, `;`
  between steps so a failed send never stops the action, every message one shlex-quoted argument.
* Shell safety by running it: a message holding ' " $ ` \\ | & > < ( ) is decoded from the crontab
  line's base64, passed by `bash -n`, then executed with stand-in `./<s>` and `sleep` scripts in a
  temp dir, and each step's argv is read back exactly; `;` and a line break are refused.
* The job list shows a chain only for a command composed byte-for-byte as the panel writes it.
* The routes on part12's app: the Schedule tab's permission, the real add/update writers with the
  host calls stubbed, the audit row with the warnings, refusals that write nothing.
* The page carries the option and its script only for those games, and the script in node.

HOW IT RUNS. No host is reached: _core.shell_as_game_user and _core._rewrite_crontab are replaced
and part12's transport tripwire is armed. The stand-in scripts run under bash in a temp dir.
"""
import base64 as _b64_174
import os as _os174
import re as _re174
import shutil as _shutil174
import subprocess as _sp174  # nosec B404 - bash over lines this part composes, with stand-in functions
import tempfile as _tmp174

from unit.part01 import _root, check, eq
from unit.part12 import (_P9_TRIPPED, P9_ADMIN, P9_FILES, P9_HOST, P9_VIEWER, _p9_arm, _p9_audit, _p9_audit_count,
                         _p9_client, _p9_delete_server, _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all)
from unit.part75 import _run_js75
from panel.ops.ssh_manager import _core as _smc174
from panel.routes import server_detail as _sd174, server_files as _sf174
from panel.services import schedule_chains as _sch174

# ── 1. which games ──────────────────────────────────────────────────────────────────────────────
_games174 = ("gmod css cs2 csgo tf2 hl2dm hldms dods l4d l4d2 ins nmrih zps fof bb2 doi nd sfc zmr cs cscz tfc "
             "dmc ns ricochet hldm ahl dod bb opfor ts vs cod coduo cod2 cod4 codwaw q3 etl rtcw wet jk2 jk3 "
             "mc pmc mcb").split()
eq("schedule chains: every Source, GoldSrc, idTech3 and Minecraft game warns with say; no other game does",
   [_sch174.say_verb(g) for g in _games174 + ["MCB", "rust", "vpmc", "wmc", "ark", "", None]],
   ["say"] * (len(_games174) + 1) + [""] * 6)

# ── 2. what is checked ──────────────────────────────────────────────────────────────────────────


def _w174(*pairs):
    return [{"minutes": m, "message": t} for m, t in pairs]


eq("schedule chains: a good chain comes back as (minutes, message), messages trimmed, digit strings read",
   _sch174.check("restart", _w174((60, " a "), ("5", "b"), (1, "c" * 120))),
   ([(60, "a"), (5, "b"), (1, "c" * 120)], None))
eq("schedule chains: the action is restart, stop or update, and there are 1 to 5 warnings",
   [_sch174.check(a, w)[1] for a, w in (
       ("start", _w174((5, "x"))), ("", _w174((5, "x"))), (None, _w174((5, "x"))), ("stop", []),
       ("stop", None), ("stop", {"minutes": 5}), ("update", _w174(*[(10 - i, "x") for i in range(6)])),
       ("update", _w174(*[(10 - i, "x") for i in range(5)])))],
   [_sch174.BAD_ACTION] * 3 + [_sch174.NO_STEPS] * 3 + [_sch174.TOO_MANY, None])
eq("schedule chains: minutes are 1-60 whole numbers and fall strictly from one warning to the next",
   [_sch174.check("restart", w)[1] for w in (
       _w174((0, "x")), _w174((61, "x")), _w174((True, "x")), _w174((5.0, "x")), _w174(("5m", "x")),
       _w174(("\u0665", "x")), _w174((-1, "x")), _w174((5, "x"), (5, "y")), _w174((1, "x"), (5, "y")),
       [5], _w174((60, "x"), (1, "y")))],
   [_sch174.BAD_MINUTES] * 7 + [_sch174.NOT_DECREASING] * 2 + [_sch174.BAD_MINUTES, None])
eq("schedule chains: a message is 1-120 printable characters with no ; (a line break, tab or escape is refused)",
   [_sch174.check("restart", _w174((5, t)))[1] for t in (
       "", "   ", "x" * 121, "a\nb", "a\rb", "a\tb", "a\x1bb", "a\x00b", "a\u2028b", "a;b", None, 5,
       "it's \"fine\" $HOME `id` \\ | & > < ( )")],
   [_sch174.BAD_TEXT] * 3 + [_sch174.CONTROL_TEXT] * 6 + [_sch174.SEMICOLON_TEXT] + [_sch174.BAD_TEXT] * 2
   + [None])

# ── 3. the composed line ────────────────────────────────────────────────────────────────────────
_line174 = _sch174.compose("u1", "cs2server", "say", "restart", [(10, "Restart in 10"), (5, "five"), (1, "one")])
eq("schedule chains: the line is cd && send ; sleep ; ... ; action, sleeps the gaps in seconds, ; between steps",
   _line174,
   "cd /home/u1 && ./cs2server send 'say Restart in 10' ; sleep 300 ; ./cs2server send 'say five' ; "
   "sleep 240 ; ./cs2server send 'say one' ; sleep 60 ; ./cs2server restart")
eq("schedule chains: a server name or account that is not a plain name, an unknown action or verb composes nothing",
   [_sch174.compose(u, s, v, a, [(1, "x")]) for u, s, v, a in (
       ("u;id", "cs2server", "say", "stop"), ("u1", "cs2 server", "say", "stop"), ("u1", "$(id)", "say", "stop"),
       ("", "cs2server", "say", "stop"), ("u1", "cs2server", "say", "start"), ("u1", "cs2server", "kick", "stop"))],
   [None] * 6)

# ── 4. the job list recognises exactly that form ────────────────────────────────────────────────
eq("schedule chains: a composed line reads back as its action and warnings",
   _sch174.parse(_line174, "u1", "cs2server", "say"),
   {"action": "restart", "steps": [{"minutes": 10, "message": "Restart in 10"}, {"minutes": 5, "message": "five"},
                                   {"minutes": 1, "message": "one"}]})
_edits174 = (_line174 + " ", _line174.replace("sleep 300", "sleep 301"),
             _line174.replace(" ; sleep 240", " && sleep 240"),
             _line174.replace("'say five'", "'kick five'"), _line174.replace("restart", "start"),
             _line174 + " ; rm -rf ~", _line174.replace("'say one'", "'say one"), _line174.replace("u1", "u2", 1),
             _line174.replace("'say five'", "'say five '"), _line174.replace("sleep 300", "sleep 3600"),
             "cd /home/u1 && ./cs2server restart", "/home/u1/backup.sh", "", None)
eq("schedule chains: a line changed by hand, another verb or account, or any other command is not a chain",
   [_sch174.parse(c, "u1", "cs2server", "say") for c in _edits174] + [_sch174.parse(_line174, "u1", "cs2server", "")],
   [None] * (len(_edits174) + 1))
eq("schedule chains: the audit detail names the schedule, the action and every warning",
   _sch174.audit_detail("0 5 * * *", "stop", [(5, "it's"), (1, "now")]),
   "0 5 * * * stop, warnings: 5 min \"it's\"; 1 min 'now'")

# ── 5. shell safety, by running the line ────────────────────────────────────────────────────────
_hostile174 = "it's \"q\" $HOME $(touch pwned1) `touch pwned2` \\ | & > pwned3 < x ( ) * ~ #"
# The stand-ins are bash functions put before the line, not executable files: a function wins over
# PATH and needs no chmod. `./cs2server` and `sleep` record each call's argv (NUL-separated) in $T/argv.
_stub174 = ("./cs2server() { printf '%s\\0' \"$#\" \"$@\" >> \"$T/argv\"; "
            "[ \"$1\" = send ] && [ -n \"${SEND_FAILS:-}\" ] && return 1; return 0; }\n"
            "sleep() { printf '%s\\0' sleep \"$@\" >> \"$T/argv\"; return 0; }\n")


def _run174(command, send_fails=False):
    """Run `command` as the recorder does (`bash -c`), in a temp dir; argv per step, sleeps and stray files."""
    tdir = _tmp174.mkdtemp(prefix="p174-")
    try:
        env = {"PATH": "/usr/bin:/bin", "T": tdir, "HOME": tdir}
        if send_fails:
            env["SEND_FAILS"] = "1"
        # /home/<u> does not exist here, so `cd` is pointed at the temp dir; everything after it is
        # the composed text exactly as bash -c receives it.
        prog = "cd() { builtin cd \"$T\"; }\n" + _stub174 + command
        res = _sp174.run(["bash", "-c", prog],  # nosec B603 B607 - the composed line under test
                       env=env, cwd=tdir, capture_output=True, timeout=20, check=False)
        try:
            with open(_os174.path.join(tdir, "argv"), encoding="utf-8") as fh:
                raw = fh.read().split("\0")[:-1]
        except FileNotFoundError:          # nothing ran at all: a line the shell could not parse
            raw = []
        steps = []
        while raw:
            if raw[0] == "sleep":
                steps.append(["sleep", raw[1]])
                raw = raw[2:]
            else:
                n = int(raw[0])
                steps.append(raw[1:1 + n])
                raw = raw[1 + n:]
        stray = sorted(f for f in _os174.listdir(tdir) if f != "argv")
        return res.returncode, steps, stray
    finally:
        _shutil174.rmtree(tdir, ignore_errors=True)


_hl174 = _sch174.compose("u1", "cs2server", "say", "update", [(5, _hostile174), (1, "bye")])
_syn174 = _sp174.run(["bash", "-n", "-c", _hl174],  # nosec B603 B607 - parse only (-n)
                     capture_output=True, timeout=10, check=False)
check("schedule chains: a message full of shell characters composes a line bash -n accepts",
      _syn174.returncode == 0, _syn174.stderr.decode(errors="replace"))
_ran174 = _run174(_hl174)
eq("schedule chains: run, each send gets the say text as ONE argument byte for byte, the sleeps the gaps, the "
   "action last; nothing the message held ran or redirected",
   _ran174, (0, [["send", "say " + _hostile174], ["sleep", "240"], ["send", "say bye"], ["sleep", "60"],
                 ["update"]], []))
eq("schedule chains: a send that fails (server stopped, console busy) does not stop the action",
   (_run174(_hl174, send_fails=True)[1] or [None])[-1], ["update"])

# ── 6. the routes ───────────────────────────────────────────────────────────────────────────────
_cs174 = _p9_new_server(P9_HOST, "p174cs", "cs2", 27015, name="p174-cs2", status="online")
_rust174 = _p9_new_server(P9_HOST, "p174rust", "rust", 28015, name="p174-rust", status="online")
_writes174, _runner174 = [], []


def _rewrite174(server, user, grep_args, add_lines, extra_pre="", drop_line=None):
    _writes174.append((user, list(add_lines), drop_line))
    return True, ""


def _shell174(server, user, inner, timeout=None, **k):
    _runner174.append((user, inner))
    return "", "", 0


def _b64_of174(line):
    m = _re174.match(r"^0 5 \* \* \* /home/p174cs/\.lgsm-cron/run [0-9a-f]{12} ([A-Za-z0-9+/=]+)$", line or "")
    return _b64_174.b64decode(m.group(1)).decode() if m else None


def _j174(r):
    return r.get_json(silent=True) or {}


_r174 = {}
_chain174 = {"action": "restart", "warnings": [{"minutes": 5, "message": _hostile174}, {"minutes": "1",
                                                                                          "message": "bye"}]}
_composed174 = _sch174.compose("p174cs", "cs2server", "say", "restart", [(5, _hostile174), (1, "bye")])
_u174 = "/api/server/%d/cron"
try:
    _p9_arm(who="part174")
    _trips174 = len(_P9_TRIPPED)
    _p9_patch_sm("_rewrite_crontab", _rewrite174)
    _p9_patch_sm("shell_as_game_user", _shell174)
    _p9_patch_sm("upgrade_managed_cron_tracking", lambda *a, **k: None)
    _p9_patch_sm("list_cron_jobs", lambda remote, user, lgsm: [])     # the read-back after each write
    _p9_patch(_sf174, "_write_refused", lambda *a, **k: None)
    _p9_patch(_sf174, "_read_refused", lambda *a, **k: None)
    _p9_patch(_sf174, "_r36c_reboot_refused", lambda *a, **k: None)
    _p9_patch(_sf174, "_sync_toggles_from_cron", lambda gs, jobs: None)
    _p9_patch(_sf174, "game_account_write_refusal", lambda *a, **k: None)   # the listing's account probe
    _A174, _F174, _V174 = _p9_client(P9_ADMIN), _p9_client(P9_FILES), _p9_client(P9_VIEWER)

    _r174["add"] = _F174.post(_u174 % _cs174, json={"schedule": "0 5 * * *", "command": "ignored",
                                                    "chain": _chain174})
    _r174["add_writes"] = list(_writes174)
    _r174["add_audit"] = _p9_audit("cron_add")
    _r174["runner"] = list(_runner174)
    _n174 = (len(_writes174), _p9_audit_count("cron_add"), len(_runner174))
    _bad174 = [{"action": "restart", "warnings": [{"minutes": 5, "message": "a;reboot"}]},
               {"action": "restart", "warnings": [{"minutes": 5, "message": "a\nreboot"}]},
               {"action": "start", "warnings": [{"minutes": 5, "message": "x"}]},
               {"action": "stop", "warnings": [{"minutes": 1, "message": "x"}, {"minutes": 5, "message": "y"}]},
               {"action": "stop", "warnings": []}, "restart", [1]]
    _r174["bad"] = [(_r.status_code, _j174(_r).get("message")) for _r in (
        _A174.post(_u174 % _cs174, json={"schedule": "0 5 * * *", "chain": c}) for c in _bad174)]
    _r174["rust"] = _A174.post(_u174 % _rust174, json={"schedule": "0 5 * * *", "chain": _chain174})
    _r174["bad_counts"] = (len(_writes174) - _n174[0], _p9_audit_count("cron_add") - _n174[1],
                           len(_runner174) - _n174[2])
    _r174["viewer"] = _V174.post(_u174 % _cs174, json={"schedule": "0 5 * * *", "chain": _chain174}).status_code
    _r174["plain"] = _A174.post(_u174 % _cs174, json={"schedule": "0 5 * * *", "command": "/home/p174cs/b.sh"})
    _r174["plain_write"] = _writes174[-1]
    _r174["plain_audit"] = _p9_audit("cron_add").detail
    _r174["update"] = _F174.post(_u174 % _cs174 + "/update", json={
        "raw": "0 5 * * * old", "schedule": "0 5 * * *",
        "chain": {"action": "stop", "warnings": [{"minutes": 2, "message": "Stopping"}]}})
    _r174["update_write"] = _writes174[-1]
    _r174["update_audit"] = _p9_audit("cron_update").detail

    _jobs174 = [{"raw": "r1", "schedule": "0 5 * * *", "command": _composed174},
                {"raw": "r2", "schedule": "0 5 * * *", "command": _composed174.replace("sleep 240", "sleep 200")},
                {"raw": "r3", "schedule": "0 5 * * *", "command": "cd /home/p174cs && ./cs2server restart"}]
    _p9_patch_sm("list_cron_jobs", lambda remote, user, lgsm: [dict(j) for j in _jobs174])
    _r174["list"] = _j174(_F174.get(_u174 % _cs174)).get("jobs")
    _r174["list_rust"] = _j174(_A174.get(_u174 % _rust174)).get("jobs")

    _p9_patch(_sd174, "_maybe_resolve_public_ip", lambda *a, **k: None)
    _p9_patch(_sd174, "_host_timezone_cached", lambda *a, **k: "")
    _p9_patch(_sf174, "_host_timezone_cached", lambda *a, **k: "")
    _p9_patch(_smc174, "run_command", lambda *a, **k: ("", "", 1))
    _r174["page_cs"] = _A174.get("/server/%d/files" % _cs174)
    _r174["page_rust"] = _A174.get("/server/%d/files" % _rust174)
    _r174["trips"] = _P9_TRIPPED[_trips174:]
finally:
    _p9_restore_all()
    for _sid174 in (_cs174, _rust174):
        _p9_delete_server(_sid174)

eq("schedule chains routes: nothing they drove reached a real transport (part12's tripwire, armed)",
   _r174.get("trips"), [])
_aw174 = _r174.get("add_writes") or [("", [""], "")]
_dec174 = _b64_of174(_aw174[0][1][0])
check("cron add route: Warn players first adds ONE base64-recorded line whose command is the composed chain "
      "(the typed command is ignored), for the Schedule tab's permission",
      _r174["add"].status_code == 200 and _j174(_r174["add"]).get("success") is True and len(_aw174) == 1
      and len(_aw174[0][1]) == 1 and _dec174 == _composed174 and _aw174[0][0] == "p174cs"
      and any("/home/p174cs/.lgsm-cron" in i for _u, i in _r174["runner"]), repr((_aw174, _dec174)))
_syn2_174 = _sp174.run(["bash", "-n", "-c", _dec174 or "("],  # nosec B603 B607 - parse only (-n)
                       capture_output=True, timeout=10, check=False)
check("cron add route: the command decoded from the crontab line passes bash -n and runs each step's argv intact",
      _syn2_174.returncode == 0 and _run174(_dec174 or "")[1] == [
          ["send", "say " + _hostile174], ["sleep", "240"], ["send", "say bye"], ["sleep", "60"], ["restart"]],
      repr(_dec174))
check("cron add route: the audit row carries the schedule, the action and every warning",
      _r174["add_audit"].success is True
      and _r174["add_audit"].detail.startswith("0 5 * * * restart, warnings: 5 min ")
      and "1 min 'bye'" in _r174["add_audit"].detail, repr(_r174["add_audit"]))
eq("cron add route: a bad chain is a 400 with the reason, and a game without a known chat command is refused",
   _r174["bad"] + [(_r174["rust"].status_code, _j174(_r174["rust"]).get("message"))],
   [(400, _sch174.SEMICOLON_TEXT), (400, _sch174.CONTROL_TEXT), (400, _sch174.BAD_ACTION),
    (400, _sch174.NOT_DECREASING), (400, _sch174.NO_STEPS), (400, _sch174.NO_STEPS), (400, _sch174.NO_STEPS),
    (400, _sch174.NOT_SUPPORTED)])
eq("cron add route: a refused chain writes nothing, installs nothing and audits nothing; a viewer gets 403",
   (_r174["bad_counts"], _r174["viewer"]), ((0, 0, 0), 403))
check("cron add route: a typed command without a chain is scheduled as before, audited with its schedule",
      _j174(_r174["plain"]).get("success") is True and _r174["plain_audit"] == "0 5 * * *"
      and "/home/p174cs/b.sh" in _r174["plain_write"][1][0], repr(_r174["plain_write"]))
_uw174 = _r174["update_write"]
check("cron update route: an edit replaces the named line with the newly composed chain and audits the warnings",
      _j174(_r174["update"]).get("success") is True and _uw174[2] == "0 5 * * * old"
      and _b64_of174(_uw174[1][0]) == "cd /home/p174cs && ./cs2server send 'say Stopping' ; sleep 120 ; "
                                      "./cs2server stop"
      and _r174["update_audit"] == "0 5 * * * stop, warnings: 2 min 'Stopping'",
      repr((_uw174, _r174["update_audit"])))
eq("cron listing: only the line composed exactly as the panel writes it is marked as a chain; on a game "
   "without a chat command nothing is",
   ([j.get("chain") for j in _r174["list"] or [{}] * 3], [j.get("chain") for j in _r174["list_rust"] or [{}] * 3]),
   ([{"action": "restart", "steps": [{"minutes": 5, "message": _hostile174}, {"minutes": 1, "message": "bye"}]},
     None, None], [None, None, None]))
_pc174 = _r174["page_cs"].get_data(as_text=True)
_pr174 = _r174["page_rust"].get_data(as_text=True)
check("files page: a game with a known chat command gets Warn players first and its script; Rust gets neither",
      _r174["page_cs"].status_code == 200 and 'id="sch-wrap"' in _pc174 and "js/server_schedule_chains.js" in _pc174
      and _pc174.index("server_schedule_chains.js") < _pc174.index("js/server_files.js")
      and _r174["page_rust"].status_code == 200 and 'id="sch-wrap"' not in _pr174
      and "server_schedule_chains.js" not in _pr174,
      repr((_r174["page_cs"].status_code, _r174["page_rust"].status_code)))

# ── 7. the script, in node ──────────────────────────────────────────────────────────────────────
with open(_os174.path.join(_root, "panel", "static", "js", "server_schedule_chains.js"), encoding="utf-8") as _fh174:
    _js174 = _fh174.read()
_node174 = _run_js75("schedule chains script: collects the warnings, checks them, fills and summarises a chain", (
    "global.window = global; global.t = s => s;\n"
    "global.tf = (s, v) => s.replace(/\\{(\\w+)\\}/g, (m, k) => v[k]);\n"
    "function node(tag) { const n = {tag, children: [], attrs: {}, hidden: false, disabled: false, value: '',\n"
    "  checked: false, required: true, className: '', title: '', parentNode: null, _l: {},\n"
    "  classList: {contains(c) { return n.className.split(' ').indexOf(c) >= 0; }},\n"
    "  appendChild(c) { c.parentNode = this; this.children.push(c); return c; },\n"
    "  removeChild(c) { this.children = this.children.filter(x => x !== c); },\n"
    "  setAttribute(k, v) { this.attrs[k] = String(v); },\n"
    "  getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; },\n"
    "  addEventListener(e, f) { this._l[e] = f; }, closest() { return null; }};\n"
    "  Object.defineProperty(n, 'textContent', {get() { return n._t || ''; },\n"
    "    set(v) { n._t = String(v); n.children = []; }});\n"
    "  return n; }\n"
    "const els = {}; const mk = id => (els[id] = els[id] || node('div'));\n"
    "['sch-on', 'sch-steps', 'sch-add', 'sch-action', 'sch-panel', 'sch-when', 'cron-cmd'].forEach(mk);\n"
    "els['sch-action'].value = 'restart'; els['sch-panel'].hidden = true;\n"
    "global.document = {getElementById: id => els[id] || null, createElement: node};\n"
    + _js174 + "\n"
    "const out = {};\n"
    "out.off = schChain.body();\n"
    "els['sch-on'].checked = true; els['sch-on']._l.change();\n"
    "out.on = schChain.body(); out.shown = !els['sch-panel'].hidden; out.cmdOff = els['cron-cmd'].disabled;\n"
    "out.cmdReq = els['cron-cmd'].required;\n"
    "els['sch-action'].value = 'stop'; els['sch-action']._l.change(); out.stop = schChain.body();\n"
    "window.schNextRun = new Date(2026, 0, 1, 5, 0); schChain.when(); out.when = els['sch-when'].textContent;\n"
    "out.semi = schChain.problem({action: 'stop', warnings: [{minutes: 5, message: 'a;b'}]});\n"
    "out.order = schChain.problem({action: 'stop',\n"
    "  warnings: [{minutes: 1, message: 'a'}, {minutes: 5, message: 'b'}]});\n"
    "out.range = schChain.problem({action: 'stop', warnings: [{minutes: 61, message: 'a'}]});\n"
    "out.good = schChain.problem(out.stop);\n"
    "out.sum = [schChain.summary({action: 'update', steps: [{minutes: 10}, {minutes: 2}]}),\n"
    "  schChain.summary({action: 'restart', steps: [{minutes: 3}]})];\n"
    "schChain.fill({action: 'update', steps: [{minutes: 9, message: 'x'}, {minutes: 4, message: 'y'}]});\n"
    "out.filled = schChain.body();\n"
    "schChain.reset(); out.reset = [schChain.body(), els['sch-panel'].hidden, els['cron-cmd'].disabled,\n"
    "  els['sch-steps'].children.length];\n"
    "console.log(JSON.stringify(out));\n"))
if _node174 is not None:
    check("schedule chains script: off posts no chain; ticked it shows 5 and 1 minute warnings with plain default "
          "text that follows the action, and the typed command is set aside",
          _node174.get("off") is None and _node174.get("shown") is True and _node174.get("cmdOff") is True
          and _node174.get("cmdReq") is False
          and _node174.get("on") == {"action": "restart", "warnings": [
              {"minutes": 5, "message": "The server restarts in 5 minutes"},
              {"minutes": 1, "message": "The server restarts in 1 minute"}]}
          and _node174.get("stop") == {"action": "stop", "warnings": [
              {"minutes": 5, "message": "The server shuts down in 5 minutes"},
              {"minutes": 1, "message": "The server shuts down in 1 minute"}]}, repr(_node174))
    check("schedule chains script: the form says the warnings start at the scheduled time and when the action lands",
          _node174.get("when", "").startswith("The warnings start at the scheduled time; the stop runs 5 minutes "
                                              "later. Next: warnings from ")
          and _node174.get("when", "").count(", stop at ") == 1, repr(_node174.get("when")))
    eq("schedule chains script: ; out-of-order and out-of-range warnings are caught before posting",
       [_node174.get(k) for k in ("semi", "order", "range", "good")],
       [_sch174.SEMICOLON_TEXT, _sch174.NOT_DECREASING, _sch174.BAD_MINUTES, ""])
    eq("schedule chains script: the list's words, editing re-opens a chain's steps, and Cancel clears them",
       [_node174.get("sum"), _node174.get("filled"), _node174.get("reset")],
       [["Update, warnings 10, 2 min before", "Restart, warning 3 min before"],
        {"action": "update", "warnings": [{"minutes": 9, "message": "x"}, {"minutes": 4, "message": "y"}]},
        [None, True, False, 0]])
