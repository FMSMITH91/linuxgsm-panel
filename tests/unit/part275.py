r"""Part 275 of the unit suite: review pass 34's second set of security fixes.

1. The batched player query (one game account asks for every server of its host) runs jq with HOME=/,
   so that account's ~/.jq cannot redefine `length` or `tostring` and decide the counts and names read
   for the other accounts' servers.
2. A LinuxGSM settings save (POST /api/server/<id>/config) takes at most 1000 settings and 1 MiB of
   text, refused whole before anything is read, and applies them in one pass over the file's lines:
   matching every key against every line cost keys x lines on the event loop.
3. World reset refuses a config with a line that can set a key through a name built from other values:
   arithmetic over another value, a `${x@P}` transform, or a command such as `printf -v "$p"` or
   `declare -i`; LinuxGSM's own config still plans.
4. The Discord bot fences the LinuxGSM output it repeats after a background action (the game account
   writes it), so a masked link or a heading in it is shown as text.
5. LinuxGSM's release notes strip HTML tags in linear time (a line of `<` with no `>` was quadratic).
6. The game config form's audit row hides the values of credential settings the LinuxGSM settings form
   already treats as secret (a GSLT in sv_setsteamaccount, a webhook, adminpass), and the form shows
   gslt / sv_setsteamaccount / webhook / auth / salt settings as password fields.

HOW IT RUNS. Routes on part12's app with its transport tripwire armed; every host call is a stub. The
batch body runs in bash with stand-in gamedig and node and the real jq; bash confirms what the world
reset configs set. Timing checks judge growth (4x the input), never wall time.
"""
import json as _json275
import os
import shutil as _shutil275
import subprocess as _sp275  # nosec B404 - bash over this part's own fixed bodies
import tempfile as _tf275
import time as _time275
import types as _types275

from unit.part01 import check, eq, skip
from unit.part12 import (P9_ADMIN, P9_GS, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_audit, _p9_client,
                         _p9_delete_server, _p9_json, _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all)
from unit.part203 import _vh203
from panel.ops.ssh_manager import _core as _core275, cron as _cron275, files as _files275
from panel.routes import server_files as _sf275
from panel.services import game_config_form as _gcf275, lgsm_cfg_form as _cmpc275
from panel.services import lgsm_players as _lgp275, lgsm_releases as _rel275, notifications as _notif275
from panel.services import world_reset as _wwr275
from panel.services.bots import discord as _dc275

_trips275 = len(_P9_TRIPPED)
_TMP275 = _tf275.mkdtemp(prefix="lgsm-unit-p275-")
_JQ275 = _shutil275.which("jq")


def _growth275(make, n):
    """How much longer the call `make(4n)` builds takes than `make(n)`'s: linear about 4, quadratic about 16.

    Each size is timed three times and the fastest kept; the small call is repeated until one timing
    reaches about 20 ms, and the large one the same number of times.
    """
    small, big = make(n), make(4 * n)
    t0 = _time275.perf_counter()
    small()
    once = _time275.perf_counter() - t0
    reps = max(1, min(4096, int(0.02 / max(once, 1e-6)) + 1))

    def best(fn):
        took = []
        for _ in range(3):
            t0 = _time275.perf_counter()
            for _ in range(reps):
                fn()
            took.append(_time275.perf_counter() - t0)
        return min(took)
    return best(big) / max(best(small), 1e-9)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. The batched player query runs jq with HOME=/
# ════════════════════════════════════════════════════════════════════════════════════════════════
_REPLY275 = {"players": [{"name": "Ann"}, {"name": "Bob"}, {"name": "Cy"}], "maxplayers": 8, "name": "Box",
             "map": "m1"}


def _batch_rig275():
    """(home, bin): a home whose ~/.jq lies about every count and name, and stand-in gamedig and node."""
    home, bindir = os.path.join(_TMP275, "home"), os.path.join(_TMP275, "bin")
    os.makedirs(home, exist_ok=True)
    os.makedirs(bindir, exist_ok=True)
    with open(os.path.join(home, ".jq"), "w", encoding="utf-8") as fh:
        fh.write('def length: 0;\ndef tostring: "forged";\n')
    lines = "\n".join(_json275.dumps({"k": k, "r": _REPLY275}) for k in (1, 2))
    stand_ins = {"gamedig": "#!/bin/sh\nexit 0\n",
                 "node": "#!/bin/sh\ncat >/dev/null\ncat <<'EOF'\n%s\nEOF\n" % lines}
    for name, body in stand_ins.items():
        path = os.path.join(bindir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions -- 0o700: an owner-only stand-in this part runs
        os.chmod(path, 0o700)  # nosec B103 - owner-only test stand-in
    return home, bindir


def _batch275():
    """player_slots_batch for two servers, its body run by bash as an account whose ~/.jq lies."""
    home, bindir = _batch_rig275()
    bodies = []

    def _shell(server, user, sh, timeout=30, selfname=None, scope=False, stdin_text=None):
        bodies.append(sh)
        env = dict(os.environ, HOME=home, PATH=bindir + os.pathsep + os.environ.get("PATH", ""))
        r = _sp275.run(["bash", "-c", sh], input=stdin_text, capture_output=True, text=True, timeout=60,  # nosec B603 B607
                       env=env, check=False)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    _p9_arm(who="part275")
    _p9_patch(_core275, "shell_as_game_user", _shell)
    _p9_patch(_core275, "_gamedig_host", lambda server: "192.0.2.75")
    try:
        got = _cron275.player_slots_batch(_types275.SimpleNamespace(id=-275, is_local=False), "gmod275",
                                          [(1, "gmod", 27015, None), (2, "gmod", 27016, None)])
    finally:
        _p9_restore_all()
        for cache in (_cron275._batch_lists, _cron275._batch_fail_streak, _cron275._game_map_cache):
            for key in [k for k in cache if -275 in (k if isinstance(k, tuple) else (k,))]:
                cache.pop(key, None)
    return got, bodies


if _JQ275:
    _bgot275, _bbodies275 = _batch275()
    eq("player batch r34: one account's ~/.jq (length 0, tostring \"forged\") does not decide the counts and "
       "names read for the host's servers: jq runs with HOME=/, and the body sudo logs is still one line",
       (_bgot275, len(_bbodies275), "\n" in "".join(_bbodies275)),
       ({1: (3, 8, "Box"), 2: (3, 8, "Box")}, 1, False))
else:
    skip("player batch r34: one account's ~/.jq does not decide the counts and names read for the host's servers",
         "no jq on this machine")


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. A settings save is bounded and applied in one pass
# ════════════════════════════════════════════════════════════════════════════════════════════════
_CFG_LINES275 = ['# slots="0"', 'slots="1"', '  slots = "2"', 'slotsx="3"', '\tip="x"', 'ip2="y"']


def _cfg_posts275(bodies):
    """POST each settings map to the config route: ([answers], [written texts], [edit_config audit rows])."""
    writes, audits = [], []
    _p9_arm(who="part275")
    _p9_patch(_files275, "_read_instance_cfg_lines", lambda *a, **k: list(_CFG_LINES275))
    _p9_patch(_files275, "_write_file_as_user",
              lambda server, user, path, content, selfname: (writes.append(content.decode()), (True, ""))[1])
    _p9_patch(_sf275, "_write_refused", lambda gs, action: None)
    _p9_patch(_lgp275, "forget", lambda *a: None)
    answers = []
    try:
        c = _p9_client(P9_ADMIN)
        for body in bodies:
            answers.append(_p9_json(c.post("/api/server/%d/config" % P9_GS, json={"settings": body})))
            audits.append(_p9_audit("edit_config"))
    finally:
        _p9_restore_all()
    return answers, writes, audits


_cfg_many275 = {"k%d" % i: "" for i in range(1001)}
_cfg_cap275 = {"k%d" % i: "" for i in range(1000)}
_cfg_long275 = {"servername": "x" * _files275.CFG_UPDATE_MAX_CHARS}
_cfg_ans275, _cfg_writes275, _cfg_audits275 = _cfg_posts275(
    [_cfg_many275, _cfg_long275, _cfg_cap275, {"slots": "5", "ip": "z", "new_key": "n", "bad-key": "q"}])
eq("config save r34 (the route): 1001 settings, or 1 MiB and more of text, are refused whole with the reason, "
   "audited as refused, and nothing is written",
   [(a.get("success"), a.get("message")) for a in _cfg_ans275[:2]]
   + [(r.success, _files275.LGSM_CONFIG_TOO_BIG in r.detail) for r in _cfg_audits275[:2]],
   [(False, _files275.LGSM_CONFIG_TOO_BIG)] * 2 + [(False, True)] * 2)
eq("config save r34 (the route): ...1000 settings are still saved (each new key appended once), and a save "
   "still rewrites every uncommented line of a key, keeps comments and look-alike keys, and skips a bad name",
   ([a.get("success") for a in _cfg_ans275[2:]], len(_cfg_writes275),
    _cfg_writes275[0].count("\n") if _cfg_writes275 else None, _cfg_writes275[1:]),
   ([True, True], 2, len(_CFG_LINES275) + 1000,
    ['# slots="0"\nslots="5"\nslots="5"\nslotsx="3"\nip="z"\nip2="y"\nnew_key="n"\n']))


def _cfg_saver275(n):
    """A call of lgsm_write_config with `n` new settings over a 50-line config (reads and writes stubbed)."""
    settings = {"n%d" % i: "v" for i in range(n)}
    server = _types275.SimpleNamespace(id=-275, is_local=False)
    return lambda: _files275.lgsm_write_config(server, "cfg275", "cfgserver", settings)


def _cfg_growth275():
    """The growth of lgsm_write_config from 250 to 1000 new settings, and whether both saved."""
    _p9_arm(who="part275")
    _p9_patch(_files275, "_read_instance_cfg_lines", lambda *a, **k: ['k%d="v"' % i for i in range(50)])
    _p9_patch(_files275, "_write_file_as_user", lambda *a, **k: (True, ""))
    _p9_patch(_lgp275, "forget", lambda *a: None)
    try:
        saved = (_cfg_saver275(250)(), _cfg_saver275(1000)())
        return _growth275(_cfg_saver275, 250), saved
    finally:
        _p9_restore_all()


_cfg_ratio275, _cfg_saved275 = _cfg_growth275()
check("config save r34: applying the settings is linear (4x the new keys took %.1fx as long; keys x lines "
      "took about 12x) and both saves went through" % _cfg_ratio275,
      _cfg_ratio275 < 8 and _cfg_saved275 == ((True, ""), (True, "")), repr((_cfg_ratio275, _cfg_saved275)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. World reset: a line that can set a key through a name built from other values
# ════════════════════════════════════════════════════════════════════════════════════════════════
_SETS_ANY275 = (
    'p="port"\nb="${p}=2"\nd="$((b))"\n',                     # arithmetic evaluates b's value: port=2
    'a="$"\np="port"\nb="${a}((${p}=2))"\nc="${b@P}"\n',      # prompt expansion runs $((port=2))
    'p="port"\nprintf -v "$p" 2\n',                           # a command setting a name from a value
    'p="port"\nb="${p}=2"\ndeclare -i d\nd="$b"\n',           # an integer variable: assignment is arithmetic
)


def _bash_port275(inst):
    """The port bash ends with after LinuxGSM's default Valheim port and `inst`."""
    r = _sp275.run(["bash", "-c", 'port="2456"\n%s\necho "$port"' % inst], capture_output=True, text=True,  # nosec B603 B607
                   timeout=20, check=False)
    return r.stdout.strip()


def _vh_plan275(inst):
    """Valheim's plan over part203's config with `inst` as the instance file: (plan, why)."""
    _p9_arm(who="part275")
    _p9_patch_sm("lgsm_cfg_texts", lambda server, user, selfname, read_only=False: _vh203(inst))
    try:
        return _wwr275.vh_plan(_types275.SimpleNamespace(remote=None, short_name="vhserver", lgsm_name="vhserver"))
    except Exception as e:  # noqa: BLE001 - reported as a value, so a crash fails the check by name
        return None, "raised %s" % type(e).__name__
    finally:
        _p9_restore_all()


eq("world reset r34: bash sets port to 2 through each of these configs, none of whose lines sets port by name "
   "(bash itself)", [_bash_port275(c) for c in _SETS_ANY275], ["2"] * len(_SETS_ANY275))
_vh_any275 = [_vh_plan275(c) for c in _SETS_ANY275]
eq("world reset r34 (the caller): Valheim's plan is refused for each, naming why (arithmetic, a ${x@P} "
   "transform, printf -v, declare -i)",
   [(plan, "name built from other values" in str(why)) for plan, why in _vh_any275],
   [(None, True)] * len(_SETS_ANY275))
_vh_fine275 = [_vh_plan275(c) for c in ("", '[ -n "${x}" ] && y="1" || y="2"\nz="$(date)"\nw="${port:-1}"\n')]
eq("world reset r34 (the caller): ...and still made for LinuxGSM's own config, and beside a `[ -n ]` test, a "
   "$(…) command substitution (a subshell) and a ${port:-1} default",
   [(bool(plan), why) for plan, why in _vh_fine275], [(True, None)] * 2)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. The Discord bot fences LinuxGSM's output in an action's outcome
# ════════════════════════════════════════════════════════════════════════════════════════════════
_LURE275 = "[Panel session expired](https://evil.example/login) ``` # Sign in again"


def _dc_outcomes275(outcomes):
    """What the bot posts after `!start` for each (ok, detail) the background action ends with."""
    sid = _p9_new_server(P9_HOST, "dc275", "gmod", 27275, name="dc275-box")
    sent = []
    _p9_patch(_notif275, "discord_bot_send", lambda tok, ch, text: sent.append(text))
    _p9_patch(_dc275, "_dc_ack", lambda *a: None)
    try:
        for ok, detail in outcomes:
            app = _types275.SimpleNamespace(
                app_context=_p9.app_context,
                _run_action=lambda gs, remote, action, actor, origin=None, on_done=None, o=ok, d=detail: (
                    on_done(o, d), (True, ""))[1])
            _dc275._handle_discord_command(app, "tok", "chan", "!start dc275-box")
    finally:
        _p9_restore_all()
        _p9_delete_server(sid)
    return [s.split("\n", 1)[1] if "\n" in s else s for s in sent]


def _dc_outside275(text):
    """The parts of a Discord message outside its code blocks (what Discord renders as markdown)."""
    return "".join(text.split("```")[0::2])


_dc_said275 = _dc_outcomes275([(False, _LURE275), (None, _LURE275), (True, ""), (False, "")])
check("discord r34: a failed or postponed action's LinuxGSM line is posted in a code block it cannot end, so "
      "its masked link and heading are text",
      len(_dc_said275) == 4 and all("](" not in _dc_outside275(s) and "#" not in _dc_outside275(s)
                                    and "[Panel session expired]" in s for s in _dc_said275[:2]),
      repr(_dc_said275))
eq("discord r34: ...a finished action, and a failure with no detail, read as before (control)",
   _dc_said275[2:], ["✅ dc275-box — start finished.", "⚠️ dc275-box — start failed."])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. LinuxGSM's release notes: tags stripped in linear time
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _notes275(n):
    """A call of parse() over one release whose notes are a line of `n` `<` and no `>`."""
    item = [{"tag_name": "v26.4.0", "body": "<" * n, "published_at": "2026-11-01T00:00:00Z"}]
    return lambda: _rel275.parse(item)


_rel_ratio275 = _growth275(_notes275, 5000)
check("release notes r34: a line of `<` with no `>` is read in linear time (4x the line took %.1fx as long)"
      % _rel_ratio275, _rel_ratio275 < 8, repr(_rel_ratio275))
eq("release notes r34: ...and the tags of an ordinary note are still dropped (control)",
   (_rel275.parse([{"tag_name": "v26.4.0", "body": "Fixed <b>bold</b> and <a href=x>a link</a>",
                    "published_at": "2026-11-01T00:00:00Z"}]) or [{}])[0].get("blocks"),
   [{"k": "p", "t": "Fixed bold and a link"}])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. The game config form's audit row and password fields
# ════════════════════════════════════════════════════════════════════════════════════════════════
_STEAM275 = "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6"
_HOOK275 = "https://discord.example/api/webhooks/1/abcdef"
_SRC275 = ('hostname "Old Name"\nsv_setsteamaccount "%s"\ndiscord_webhook_url "%s"\nadminpass "orig-a1"\n'
           'sv_cheats "0"\n' % (_STEAM275, _HOOK275))
_REL275 = "serverfiles/csgo/cfg/csgoserver.cfg"


def _gcf_fields275(content):
    form = _gcf275.build(_REL275, content)
    return {} if form is None else {f["key"]: f for g in form["groups"] for f in g["fields"]}


def _gcf_save275():
    """Save four changed fields through the form route: (answer, the edit_file audit row)."""
    sid = _p9_new_server(P9_HOST, "gcf275", "csgo", 27375, name="gcf275-box")
    fid = {k: str(f["id"]) for k, f in _gcf_fields275(_SRC275).items()}
    _p9_arm(who="part275")
    _p9_patch_sm("read_file", lambda server, user, relpath, max_bytes=1048576: (_SRC275, None))
    _p9_patch_sm("write_file", lambda server, user, relpath, content, selfname=None: (True, ""))
    _p9_patch(_sf275, "_write_refused", lambda *a, **k: None)
    try:
        r = _p9_client(P9_ADMIN).post("/api/server/%d/game-config/form" % sid, json={
            "path": _REL275, "hash": _gcf275.content_hash(_SRC275), "changes": {
                fid["hostname"]: "New Name", fid["sv_setsteamaccount"]: "F" * 32,
                fid["discord_webhook_url"]: _HOOK275 + "x", fid["adminpass"]: "next-b2"}})
        return _p9_json(r), _p9_audit("edit_file")
    finally:
        _p9_restore_all()
        _p9_delete_server(sid)


_gcf_ans275, _gcf_row275 = _gcf_save275()
check("game config form r34 (the route): the audit row names the changed credential settings as changed only "
      "(no GSLT, webhook or adminpass value, old or new) and still shows an ordinary setting's values",
      _gcf_ans275.get("success") is True and _gcf_row275.detail.count("changed (hidden)") == 3
      and "hostname: Old Name -> New Name" in _gcf_row275.detail
      and not any(v in _gcf_row275.detail for v in (_STEAM275, "F" * 20, "webhooks/1", "orig-a1", "next-b2")),
      repr((_gcf_ans275.get("success"), _gcf_row275.detail)))
_gcf_names275 = ("gslt", "sv_setsteamaccount", "discord_webhook_url", "DiscordWebhook", "steam_auth", "server_salt")
eq("game config form r34: gslt, sv_setsteamaccount, webhooks, auth and salt are password fields; a switch, "
   "keyboard_layout, passive_mobs and author_name are not",
   ([_gcf275.is_secret_key(k) for k in _gcf_names275],
    [_gcf275.is_secret_key(k) for k in ("keyboard_layout", "passive_mobs", "author_name")],
    _gcf_fields275(_SRC275)["sv_cheats"]["secret"]),
   ([True] * len(_gcf_names275), [False] * 3, False))
eq("game config form r34: the one credential-name test both forms share calls each of these a secret",
   [_cmpc275.is_secret_name(k) for k in _gcf_names275 + ("adminpass",)], [True] * (len(_gcf_names275) + 1))

_shutil275.rmtree(_TMP275, ignore_errors=True)
check("part275: no check reached a real host", len(_P9_TRIPPED) == _trips275, repr(_P9_TRIPPED[_trips275:][:4]))
