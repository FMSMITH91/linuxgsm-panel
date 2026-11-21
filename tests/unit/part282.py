"""Part 282 of the unit suite: runtime fixes of review pass 35.

1. An add-on Update writes its record only once the image (and BlueMap's client file) is there: a
   failed pull or build left a record naming the new image, so the card said "Up to date" and hid Update.
2. A whole-file SFTP upload over an existing file keeps the free-space headroom: it is written beside
   the file, which keeps its bytes until the close.
3. BlueMap's card shows the render threads config/core.conf sets, not the install's default.
4. A B3 Kick or Warn is refused before B3 is asked when another B3 player's stored name is one the
   listed player's name can also mean; the player view is read again after an action.
5. The add-on page gate is per add-on; a WebSocket whose browser went before the splice closes the
   add-on's stream.
6. A cfg key set again under a later `// .... Title .... //` heading is one field, the last line.
7. An idTech3 Kick or Ban whose console list could not be read says so (not "the player left").
8. B3's penalty alert has its own push title and text; every alert event has one.
9. A value saved through the Settings tab with backslash escapes no longer refuses every world reset.
10. Root's crontab refused for its size says so, not "line N is not a cron job" about a valid comment.
11. The database browser's read-only rows say where to read a cut value instead of a dead "Show all".
12. A Backup button run and a queued stop/restart being run wait for each other.
13. A game restore cut by a signal during its clean-up keeps the restore.
14. sign-release names no release when the remote's tags can't be read, or when an existing
    release's tag names another commit.
15. BlueMap reads the world's Minecraft version from the server jar or the rotated logs when
    latest.log has no "Starting minecraft server version" line (a rotation, a fresh log).

Nothing here reaches a host.
"""
import errno as _errno282
import gzip as _gz282
import json as _json282
import os
import shutil as _sh282
import socket as _so282
import stat as _stat282
import subprocess as _sp282  # nosec B404 - bash and node over this part's own throwaway files
import tempfile as _tf282
import zipfile as _zip282

from unit.part01 import check, eq, skip
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, P9_HOST, _P9Thread, _p9, _p9_arm, _p9_audit, _p9_client, _p9_delete_server,
                         _p9_drain, _p9_json, _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all,
                         _p9_threading)
from unit.part47 import _cut47
from unit.part190 import _NAME190, _U190, _UNDO190, _Sb190, _missing190
from unit.part221 import _node221
from unit import part247 as _p247
from unit.part272 import _host272, _named272, _puts272, _writes272
from unit.part278 import _act278, _fixture278, _post278, _socket_stub278
from panel.core import panel_state as _ps282
from panel.ops.debug_report import data as _drd282
from panel.ops.ssh_manager import _core as _core282, game as _game282
from panel.routes import _shared as _sh_282, addon_web as _raw282, addons as _ra282, panel_backup as _pb282
from panel.routes import server_detail as _sd282, server_files as _sfr282
from panel.services import addon_web as _aw282, addon_web_http as _http282, addons as _ad282
from panel.services import addons_bluemap as _bm282
from panel.services import game_restore as _grs282, notifications as _nt282, push_alerts as _pa282
from panel.services import root_cron as _rc282, sftp_files as _sf282, world_reset as _wr282
from panel.security import privileged as _pv282

_TMP282 = _tf282.mkdtemp(prefix="lgsm-unit-282-")
_U282 = "u282"


def _bash282(sh, path_first, cwd=None, timeout=60):
    return _sp282.run(["bash", "-c", sh], capture_output=True, text=True, timeout=timeout, cwd=cwd,  # nosec B603 B607
                      env=dict(os.environ, PATH=path_first + ":/usr/bin:/bin"), check=False)


def _stub282(bindir, name, text):
    os.makedirs(bindir, exist_ok=True)
    with open(os.path.join(bindir, name), "w", encoding="utf-8") as fh:
        fh.write("#!/bin/bash\n" + text)
    # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
    os.chmod(os.path.join(bindir, name), 0o700)  # nosec B103 - this part's own stub, its owner only


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. An Update's record is written once the image is there
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _update_sh282(podman_rc):
    """Run a pulled add-on's (BlueMap's) Update shell under bash with a podman that exits `podman_rc`: (rc, output, record)."""
    root = os.path.join(_TMP282, "upd%d" % podman_rc)
    home, run = os.path.join(root, "home"), os.path.join(root, "run")
    os.makedirs(run, exist_ok=True)
    bus = _so282.socket(_so282.AF_UNIX, _so282.SOCK_STREAM)
    bus.bind(os.path.join(run, "bus"))
    bindir = os.path.join(root, "bin")
    _stub282(bindir, "podman", "exit %d\n" % podman_rc)
    _stub282(bindir, "systemctl", 'case "$*" in *is-active*) echo active;; *NRestarts*) echo 0;; esac\nexit 0\n')
    _stub282(bindir, "sleep", "exit 0\n")
    _stub282(bindir, "journalctl", "exit 0\n")
    meta = os.path.join(home, _ad282.HOME_DIR, "bluemap", _ad282.META_FILE)
    os.makedirs(os.path.dirname(meta), exist_ok=True)
    with open(meta, "w", encoding="utf-8") as fh:
        fh.write('{"image": "old"}\n')
    sh = _ad282.reconfigure_sh(_U282, "bluemap", "UNIT", '{"image": "new"}\n', {}, {},
                               {"rebuild": True, "old_image": "old"})
    sh = sh.replace(_ad282._ENV, "export XDG_RUNTIME_DIR=%s; cd %s || exit 1; " % (run, home))
    sh = sh.replace("/home/" + _U282, home)
    try:
        r = _bash282(sh, bindir)
    finally:
        bus.close()
    with open(meta, encoding="utf-8") as fh:
        return r.returncode, r.stdout, fh.read()


def _update_record282():
    failed, ok = _update_sh282(1), _update_sh282(0)
    eq("add-on Update (bash): a pull that fails leaves the record naming the image still in use (the card offers "
       "Update again); one that works writes the new record (it was written before the pull, so a failed Update "
       "read 'Up to date')",
       [(failed[0], "ADDON_PULL_FAILED" in failed[1], failed[2]), (ok[0], "ADDON_INSTALLED" in ok[1], ok[2])],
       [(23, True, '{"image": "old"}\n'), (0, True, '{"image": "new"}\n')])
    sh = _ad282.reconfigure_sh(_U282, "b3", "UNIT", "{}", {}, {}, {"reload": "P282RELOAD; ", "extra": "P282EXTRA; "})
    put = sh.index(_ad282.META_FILE)
    check("add-on change: the record goes in after the client file and before a settings reload (which exits "
          "before the unit is written)", sh.index("P282EXTRA") < put < sh.index("P282RELOAD"), sh[put - 200:put + 80])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. SFTP: a staged upload does not count the old file as free space
# ════════════════════════════════════════════════════════════════════════════════════════════════
class _Vfs282:
    """A session for Files.open: one game account, a backend with `free` bytes free and `size` in the file."""

    def __init__(self, free, size):
        """A session over a backend with a regular file of `size` bytes."""
        self.open_count = 0
        self.target = type("T", (), {"user": "p282u", "selfname": "p282srv", "sid": 282})()
        self.backend = type("B", (), {
            "stat": staticmethod(lambda real: {"mode": _stat282.S_IFREG | 0o644, "size": size}),
            "free_bytes": staticmethod(lambda path: free),
            "open": staticmethod(lambda path, pflags, attrs=None: object())})()

    def resolve(self, path, write=False, follow=True):
        """(target, backend, real, rel) for `path` under the account's home."""
        rel = path.strip("/").split("/", 1)[1]
        return self.target, self.backend, "/home/p282u/" + rel, rel

    def audit(self, target, action, detail, success=True):
        """No audit rows are looked at here."""


def _sftp_staged282():
    gib, slack = 1024 ** 3, _sf282.sc.FREE_SPACE_SLACK
    files = _sf282.Files({"cap_mb": 10 * 1024})
    got = [files.open(_Vfs282(2 * gib, 3 * gib), "/P282/serverfiles/maps/big.bsp", flags, None).info["limit"]
           for flags in (os.O_WRONLY | os.O_CREAT | os.O_TRUNC, os.O_WRONLY)]
    eq("sftp: a whole-file upload over a 3 GiB file with 2 GiB free may reach 2 GiB less the headroom (it is "
       "staged beside the file, which keeps its bytes); a write into the file itself still counts its size",
       got, [2 * gib - slack, 5 * gib - slack])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. BlueMap's render threads as core.conf sets them
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _threads_read282(conf):
    root = os.path.join(_TMP282, "bm%d" % abs(hash(conf)))
    os.makedirs(os.path.join(root, _ad282.HOME_DIR, "bluemap", "config"), exist_ok=True)
    with open(os.path.join(root, _ad282.HOME_DIR, "bluemap", "config", "core.conf"), "w", encoding="utf-8") as fh:
        fh.write(conf)
    r = _bash282(_ad282._world_status_sh("bluemap"), os.path.join(root, "nobin"), cwd=root)
    meta = _ad282._b64('{"kind": "bluemap"}')
    st = _ad282.parse_status("meta.bluemap=%s\nstate.bluemap=active\n" % meta + r.stdout)
    got = st["addons"].get("bluemap") or {}
    return got.get("render_threads"), _ra282._bluemap_fields({}, got)["render_threads"]


def _bluemap_threads282():
    got = [_threads_read282(c) for c in ("accept-download: true\nrender-thread-count: 4\n",
                                        "  render-thread-count = 3 # more renders faster\n",
                                        "render-thread-count: -2\n", "accept-download: true\n")]
    eq("BlueMap card: the render threads are read from config/core.conf as set there (4, 3); a value that is not a "
       "whole number from 1 (BlueMap's own reading of zero or less) or none is not shown as a number",
       got, [(4, 4), (3, 3), (None, None), (None, None)])
    src = open(os.path.join(_root, "panel", "static", "js", "server_addons.js"), encoding="utf-8").read()
    check("BlueMap card (js): a missing thread count shows the sentence naming the setting, never a made-up 1",
          "a.render_threads || 1" not in src and "Render threads: as render-thread-count" in src, "server_addons.js")


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. B3 Kick/Warn: the identity is checked before B3 acts; the view is read again
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _b3_namesake282():
    sid = _fixture278()
    _p9_arm(who="part282")
    try:
        done = '{"id": 1, "ok": true, "result": {"cid": "3", "client_id": 12}}\n'
        cases = []
        for listed, others in (({"name": "Bob", "num": 3}, ["Bob"]), ({"name": "^1Bob", "num": 3}, ["Bob"]),
                               ({"name": "Bob", "num": 3}, ["Bobby", "bob"]), ({"name": "Bob", "num": 3}, [])):
            seen = _socket_stub278(done, listed, name="Bob", namesakes=others)
            st, d = _post278(P9_ADMIN, sid, "kick", {"reason": "camping"})
            cases.append((st, d.get("error") or d.get("message"), len(seen["socket"])))
        audit = _p9_audit("b3_kick").detail
        many = _socket_stub278(done, {"name": "Bob", "num": 3}, name="Bob",
                               namesakes=["x"] * (_act278._b3.NAMESAKES_MAX + 1))
        full = _post278(P9_ADMIN, sid, "warn", {"reason": "language"})[0], len(many["socket"])
    finally:
        _p9_restore_all()
        _p9_delete_server(sid)
    eq("b3 kick: another B3 player stored as the listed player's name (also as a colour-coded console name) is "
       "refused before B3 is asked; a name the listed one can't mean (Bobby, another case) or none lets it go on",
       cases, [(409, _act278.S_NAMESAKE, 0), (409, _act278.S_NAMESAKE, 0), (200, "B3 kicked the player.", 1),
               (200, "B3 kicked the player.", 1)])
    eq("b3 warn: a full read of namesakes (the rest unread) refuses too", full, (409, 0))
    check("b3 kick: the namesake refusal is audited as that", "another B3 player has that name" in
          (_p9_audit("b3_warn").detail or "") and "done" in (audit or ""), repr(audit))


def _b3_reread282():
    src = open(os.path.join(_root, "panel", "static", "js", "b3_players.js"), encoding="utf-8").read()
    prog = ("var calls = [], window = {}, st = {busy: false};\nfunction T(s){ return s; }\n"
            "function el(){ return {value: ''}; }\nfunction api(p){ return p; }\n"
            "function say(t){ calls.push('say:' + t); }\nfunction refused(){ return false; }\nfunction failed(){ return false; }\n"
            "function postJson(u){ calls.push('post:' + u); return Promise.resolve({success: true, message: 'lifted'}); }\n"
            "window.confirmDialog = function (o) { o.onConfirm(); };\n"
            "window.b3pPlayer = function (id) { calls.push('read:' + id); return Promise.resolve(true); };\n"
            + _cut47(src, "var ASK = ") + "\n" + _cut47(src, "var TITLE = ") + "\n"
            + _cut47(src, "window.b3pAct = function") + "\n"
            "window.b3pAct('unban', 12).then(function () { console.log(JSON.stringify(calls)); });\n")
    got = _node221("b3 player view: read again after an action", prog)
    if got is not None:
        eq("b3 player view (node): after an Unban that worked the player is read again, then B3's answer is said "
           "(the lifted ban stayed 'Active' with its Unban button)", got,
           ["say:Asking B3\u2026", "post:/players/12/unban", "read:12", "say:lifted"])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. The add-on page gate per add-on; a WebSocket that never began
# ════════════════════════════════════════════════════════════════════════════════════════════════
class _End282:
    """One end of a splice: `sendall` raises when `dead`; records whether it was closed."""

    def __init__(self, dead=False):
        """An end that is open."""
        self.dead, self.closed = dead, False

    def sendall(self, data):
        """Raise as a socket whose peer went, when dead."""
        if self.dead:
            raise BrokenPipeError(_errno282.EPIPE, "the browser went")

    def close(self):
        """Note the close."""
        self.closed = True


def _addon_web282():
    with _aw282._GATES_LOCK:
        saved = dict(_aw282._GATES)
        _aw282._GATES.clear()
    try:
        iw = _aw282.gate(282, 21002, _ad282.IW4MADMIN)
        bm = _aw282.gate(282, 21002, _ad282.BLUEMAP)
        sizes = [g._initial_value for g in (iw, bm)]
    finally:
        with _aw282._GATES_LOCK:
            _aw282._GATES.clear()
            _aw282._GATES.update(saved)
    eq("add-on page gate: a port first used by IW4MAdmin and then by BlueMap gives each its own number of "
       "connections (BlueMap was held to one for as long as the panel ran)", sizes,
       [_aw282.WEB[_ad282.IW4MADMIN]["connections"], _aw282.WEB[_ad282.BLUEMAP]["connections"]])
    stream, sock = _End282(), _End282(dead=True)
    head = type("H", (), {"headers": [], "rest": b"", "status": 101})()
    proxy = _raw282.AddonWebProxy(None, _p9)
    _p9_patch(_raw282, "_client_socket", lambda environ: sock)
    try:
        answer = proxy._switch({}, stream, head, "t282")
    finally:
        _p9_restore_all()
    up, client = _End282(), _End282(dead=True)
    _http282.splice(client, up, first=b"hello", still_allowed=lambda: True, recheck=1)
    eq("add-on WebSocket: a browser gone before the 101 reached it, or before the add-on's first bytes did, closes "
       "the add-on's stream (it stayed open until the add-on dropped the idle WebSocket)",
       (answer, stream.closed, up.closed, client.closed), ([], True, True, True))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. A cfg key set again under a later heading
# ════════════════════════════════════════════════════════════════════════════════════════════════
_CFG282 = ('// ............................. Basic Settings ............................. //\n'
           'hostname "p282"\nrcon_password "first"\nsv_cheats 0\n'
           '// ............................. Added Later ............................. //\n'
           'RCON_PASSWORD "last"\n')


def _cfg_headings282(sid):
    writes = []
    _p9_arm(who="part282")
    _p9_patch_sm("read_file", lambda server, user, rel, **k: (_CFG282, None))
    _p9_patch_sm("write_file", lambda server, user, rel, content, **k: writes.append(content) or (True, ""))
    _p9_patch(_sfr282, "_read_refused", lambda *a, **k: None)
    _p9_patch(_sfr282, "_write_refused", lambda *a, **k: None)
    c, url = _p9_client(P9_ADMIN), "/api/server/%d/game-config/form" % sid
    try:
        got = _p9_json(c.get(url + "?path=serverfiles/cfg/p282.cfg"))
        fields = [(f["key"], f["value"], f["id"]) for g in (got.get("form") or {}).get("groups", [])
                  for f in g["fields"]]
        rid = [i for k, _v, i in fields if k.lower() == "rcon_password"]
        saved = _p9_json(c.post(url, json={"path": "serverfiles/cfg/p282.cfg", "hash": got["form"]["hash"],
                                           "changes": {str(rid[-1]): "rotated"}})) if rid else {}
    finally:
        _p9_restore_all()
    eq("config form: an RCON password set again under a later `// .... Title .... //` heading is one field, the "
       "last line, and saving it changes that line (the heading kept two fields, and the first was the old one)",
       ([(k, v) for k, v, _i in fields], saved.get("success"), writes[-1:]),
       ([("hostname", "p282"), ("sv_cheats", "0"), ("RCON_PASSWORD", "last")], True,
        [_CFG282.replace('"last"', '"rotated"')]))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 7. idTech3: an unread console list is not "the player left"
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _idt3_unread282():
    sent = []
    _p9_patch(_core282, "send_console_command", lambda server, user, cmd, **k: sent.append(cmd) or ("", "", 0))
    _p9_patch(_game282, "console_player_list", lambda *a, **k: None)
    try:
        got = _game282.moderate(None, "u282", "cod4", "kick", target="Griefer", num="3")
    finally:
        _p9_restore_all()
    eq("moderation (idTech3): a Kick by slot whose console list could not be read is refused as that (not 'they "
       "left'), and sends nothing", (got, sent), ((False, _game282.IDT3_LIST_UNREAD), []))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 8. Push words for every alert event
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _push_words282():
    eq("push alerts: every alert event a user can tick has its own title (b3_penalty was titled with its raw key)",
       sorted(k for k in _nt282.EVENTS if k not in _pa282._TEXT), [])
    with _p9.app_context():
        note = _pa282._event_note("en", "b3_penalty", None, None)
    eq("push alerts: B3's penalty push says what happened and names no player", note[:2],
       ("B3 penalised a player", "?: B3 banned, temporarily banned or kicked a player."))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 9. A Settings-tab value with backslash escapes
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _escaped_values282():
    cfg = ('servername="Joe\'s \\"Hardcore\\" Survival (let\'s go!)"\nserverpassword="\\$[ecret"\n'
           'worldname="w282"\n')
    got = _wr282.cfg_values([cfg], ["worldname"])
    bad = [_wr282.cfg_values([cfg + line], ["worldname"])[0] for line in ('x="$[1]"\n', 'x="a\\\\$((p=2))"\n',
                                                                          'printf -v worldname x\n')]
    eq("world reset: a server name saved through the Settings tab (escaped quotes, words after a bracket) and an "
       "escaped $[ read as plain values; arithmetic, an escaped backslash before it, or printf -v still refuse",
       (got, bad), (({"worldname": "w282"}, None), [None, None, None]))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 10. Root's crontab: the size is said, not a valid comment
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _root_cron282():
    latin1 = "# caf\udce9\n"
    big = latin1 + "# filler\n" * (_pv282.ROOT_CRON_MAX_LINES - 1) + "* * * * * true\n"
    bad = "# fine\nnot a cron line\n"
    eq("root cron: a crontab too long whose line 1 is a Latin-1 comment (installed as it is) is refused for its "
       "size; a line the install refuses is named by its number",
       [str(_rc282._invalid(big)), str(_rc282._invalid(bad))],
       [str(_rc282.TOO_BIG), str(_rc282.i18n.Sentence(_rc282.BAD_LINE, n=2))])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 11. The database browser's keyless rows
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _dbm_keyless282():
    src = open(os.path.join(_root, "panel", "static", "js", "databases_manager.js"), encoding="utf-8").read()
    prog = ("var made = [];\nfunction T(s){ return s; }\nfunction TF(s){ return s; }\nfunction raw(e){ return e; }\n"
            "function node(t, c, x){ return {t: t, text: x || '', kids: [], disabled: false, textContent: '',"
            " appendChild: function (k) { this.kids.push(k); return k; }}; }\n"
            "function button(label, cls, act, args){ made.push(act); return node('button', cls, label); }\n"
            "var document = {createTextNode: function (x) { return node('#text', null, x); }};\n"
            "var boxes = {}; function el(id){ return boxes[id] || (boxes[id] = node('div')); }\n"
            "var st = {canEdit: false, page: 0};\n"
            + _cut47(src, "function cellNode(") + "\n" + _cut47(src, "function drawRows(") + "\n"
            "var t = {readonly: true, columns: [{name: 'a'}]}, out = [];\n"
            "[null, {k: 1}].forEach(function (key) { made = []; drawRows(t, {columns: ['a'], more: false, rows: "
            "[{key: key, cells: [{text: 'long', more: true}]}]}); out.push(made.join(',') || 'none'); });\n"
            "console.log(JSON.stringify(out));\n")
    got = _node221("databases browser: keyless rows", prog)
    if got is not None:
        eq("databases browser (node): a cut value in a row with no key (a view, no primary key, a binary key) gets "
           "no 'Show all' (it did nothing); a keyed row keeps it", got, ["none", "dbmShowAll"])
    check("databases browser: the keyless row's note is the SQL-box sentence",
          "Too long to show here: use the SQL box." in src, "databases_manager.js")


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 12. A Backup button run and a queued stop/restart
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _backup_queued282(sid):
    teed, ran = [], []
    _p9_arm(who="part282")
    _p9_patch(_sd282, "threading", _p9_threading(_P9Thread))
    _p9_patch(_sd282, "_db_dump_before", lambda *a, **k: None)
    _p9_patch(_sd282, "_run_teed", lambda app, remote, s, short, action, *a, **k: teed.append(action) or ("", "", 0))
    _p9_patch(_sh_282, "get_server_status", lambda *a, **k: "online")
    _p9_patch(_sh_282, "sm_player_count", lambda *a, **k: 0)
    _p9_patch(_sh_282, "_run_queued_action", lambda app, gs: ran.append(gs.id))
    try:
        with _p9.app_context():
            gs = _sd282.db.session.get(_sd282.GameServer, sid)
            with _ps282.r36j_route_job(sid, "queued"):
                _sd282._bg_action(_p9, gs, gs.remote, "backup")
                _p9_drain()
            held = list(teed)
            _sd282._bg_action(_p9, gs, gs.remote, "backup")
            _p9_drain()
            with _ps282.r36j_route_job(sid, "action"):
                _sh_282._settle_queued_action(_p9, gs)
            waited = list(ran)
            _sh_282._settle_queued_action(_p9, gs)
    finally:
        _p9_restore_all()
    eq("Backup button: run while a queued stop/restart is being run it is refused (LinuxGSM's backup started a "
       "server queued to stop again); a queued run waits while a button action is registered, before its tail "
       "shows; both run otherwise (controls)", (held, teed, waited, ran), ([], ["backup"], [], [sid]))
    eq("full backup: the held clause names every job that holds a backup, and the debug report still counts it",
       _drd282._full_counts_text(_drd282._FULL_COUNTS_RE.match(_held_summary282())),
       "0 backed up, 0 failed, 0 skipped, 1 held by a scheduled wipe, a restore, a queued stop or restart, or an "
       "uninstall")


def _held_summary282():
    tally = _pb282._FullBackupTally()
    tally.held = ["p282"]
    return tally.summary()


def _server_cases282():
    sid = _p9_new_server(P9_HOST, "cod4p282", "cod4", 28282, name="p282-cod4")
    try:
        _cfg_headings282(sid)
        _backup_queued282(sid)
    finally:
        _p9_delete_server(sid)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 13. A restore cut by a signal while it removes the aside copy
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _restore_signal282():
    if _missing190:
        skip("game restore: a signal during the clean-up keeps the restore", "missing tools: %s" % _missing190)
        return
    sb = _Sb190()
    beat = _grs282.HEARTBEAT
    _grs282.HEARTBEAT = 1
    try:
        ready = sb.vet()[1][1]
        with open(os.path.join(sb.bdir, _UNDO190), "wb") as f:
            f.write(b"undo")
        rs = _grs282.restore_script(_U190, _U190, _NAME190, ready["t0"], ready["need"], _UNDO190, busy_polls=1,
                                    members=ready["members"])
        cut = rs.replace('echo done > "$st"; then ', 'echo done > "$st"; then kill -TERM $$; ', 1)
        out, rc = sb.run(cut)
        wd = os.path.join(sb.home, _grs282.WORK_DIR)
        left = sorted(f for f in (os.listdir(wd) if os.path.isdir(wd) else []) if f != "panel-restore.lock")
        got = (cut != rs, rc != 0, sb.read("serverfiles/world/region/r.0.mca"),
               sb.read("serverfiles/world/region/r.1.mca"), left, "ROLLBACK" in out)
    finally:
        _grs282.HEARTBEAT = beat
        sb.gone()
    eq("game restore (bash): a SIGTERM after the switch is noted done keeps the restored files and removes the "
       "aside copy (the trap moved the old files back over a finished restore)", got,
       (True, True, "world v1", None, [], False))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 14. sign-release: no name from a remote it could not read, nor from another commit's release
# ════════════════════════════════════════════════════════════════════════════════════════════════
_FAKEGH282 = r"""
printf '%s\n' "$*" >> "$FAKEGH_LOG"
if [ "$1" = release ] && [ "$2" = view ]; then
    [ -n "${FAKEGH_VIEW_ALL:-}" ] && exit 0
    git --git-dir "$FAKEGH_BARE" rev-parse -q --verify "refs/tags/$3" >/dev/null && exit 0
    exit 1
fi
if [ "$1" = release ] && [ "$2" = create ]; then git --git-dir "$FAKEGH_BARE" tag "$3" "$5"; fi
exit 0
"""


def _sign_release282():
    git = _sh282.which("git")
    if not (_sh282.which("ssh-keygen") and git):
        skip("sign-release: naming when the remote can't be read", "git or ssh-keygen is not installed")
        return
    saved = _p247._TMP247
    _p247._TMP247 = os.path.join(_TMP282, "sign282")
    os.makedirs(_p247._TMP247)
    try:
        rig = _p247._sign_repo247()
    finally:
        _p247._TMP247 = saved
    with open(rig[4], "w", encoding="utf-8") as fh:
        fh.write(_FAKEGH282)
    shim = os.path.join(rig[0], "shim")
    _stub282(shim, "git", '[ "$1" = ls-remote ] && [ -n "${P282_LSREMOTE_FAIL:-}" ] && exit 128\nexec %s "$@"\n' % git)
    path = shim + ":" + os.environ.get("PATH", "/usr/bin:/bin")
    a = _p247._commit247(rig[3], 41)
    r_a = _p247._sign247(rig, a, PATH=path)
    b = _p247._commit247(rig[3], 42)
    r_b = _p247._sign247(rig, b, PATH=path, P282_LSREMOTE_FAIL="1")
    c = _p247._commit247(rig[3], 43)
    r_c = _p247._sign247(rig, c, PATH=path, FAKEGH_VIEW_ALL="1")
    named = [_p247._named247(rig, x) for x in (a, b, c)]
    src = open(os.path.join(_root, "tools", "sign-release.sh"), encoding="utf-8").read()
    fns = src[src.index("tag_commit() {"):src.index("\n}\n", src.index("release_tag() {")) + 3]
    direct = _p247._run142(["bash", "-c", fns + "cd %s && release_tag %s %s" % (rig[3], b, os.path.join(rig[0], "gone.git"))])
    eq("sign-release: release_tag on a remote that does not answer fails and names nothing (it gave the day's first "
       "name, read as 'no such tag')", (direct.returncode != 0, direct.stdout.strip()), (True, ""))
    eq("sign-release: with the remote's tags unreadable, a second commit of the day gets no name (it was given the "
       "first release's name for good); a release found for a name whose tag is not this commit names nothing",
       [(r.returncode, n) for r, n in zip((r_a, r_b, r_c), named)],
       [(0, (True, "2026.3.4")), (0, (True, None)), (0, (True, None))])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 15. BlueMap: the world's version when latest.log has no start line
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _mc_home282(name, jar=None, rotated=None):
    """A stand-in Minecraft home whose latest.log has no start line: (home, the probe's world lines under bash)."""
    home = os.path.join(_TMP282, name)
    os.makedirs(os.path.join(home, "serverfiles", "logs"))
    os.makedirs(os.path.join(home, "serverfiles", "world"))
    with open(os.path.join(home, "serverfiles", "server.properties"), "w", encoding="utf-8") as fh:
        fh.write("level-name=world\n")
    with open(os.path.join(home, "serverfiles", "logs", "latest.log"), "w", encoding="utf-8") as fh:
        fh.write("[12:00:00] [Server thread/INFO]: Done (3.1s)! For help, type \"help\"\n")
    if jar:
        with _zip282.ZipFile(os.path.join(home, "serverfiles", jar[0]), "w") as z:
            z.writestr("version.json", _json282.dumps({"id": jar[1], "name": jar[1], "world_version": 4189}))
    for i, text in enumerate(rotated or ()):
        with _gz282.open(os.path.join(home, "serverfiles", "logs", "2026-11-1%d-1.log.gz" % i), "wt") as fh:
            fh.write(text)
        os.utime(os.path.join(home, "serverfiles", "logs", "2026-11-1%d-1.log.gz" % i), (1_700_000_000 + i,) * 2)
    r = _bash282(_bm282.world_sh(), os.path.join(home, "nobin"), cwd=home)
    return r.stdout


def _bluemap_version282():
    start = "[Server thread/INFO]: Starting minecraft server version %s\n"
    outs = {"jar": _mc_home282("mcjar", jar=("paper-1.21.4-100.jar", "1.21.4")),
            "rotated": _mc_home282("mcrot", rotated=(start % "1.21.3", start % "1.21.4")),
            "none": _mc_home282("mcnone")}
    read = {k: _ad282.kv_lines(v).get("mcver") for k, v in outs.items()}
    eq("BlueMap probe (bash): with no start line in latest.log the version is the server jar's version.json id",
       read["jar"], "1.21.4")
    eq("BlueMap probe (bash): ...with no jar that has one, the newest rotated log's start line; else none",
       (read["rotated"], read["none"]), ("1.21.4", ""))
    sid = _p9_new_server(P9_HOST, "mcp282", "mc", 25582, name="p282-mc")
    got = []
    try:
        for k in ("jar", "none"):
            probe = ("os=24.04\npodman=podman version 4.9.3\nuid=1001\ngid=1001\nports= 21008\nsplice=1\n"
                     + outs[k])
            _p9_arm(who="part282")
            calls = _host272(probe)
            r = _p9_client(P9_ADMIN).post("/api/server/%d/addons/bluemap/install" % sid, json={"accept_eula": True})
            _p9_drain()
            meta = _json282.loads(_named272(_puts272(_writes272(calls)[0]), "/addon.json") or "{}")
            row = _p9_audit("addon_install")
            got.append((r.status_code, row.success, "Minecraft version" in (row.detail or ""), meta.get("mc_version")))
            _p9_restore_all()
    finally:
        _p9_restore_all()
        _p9_delete_server(sid)
    eq("BlueMap install (route): a rotated latest.log with the server jar's version installs for that version; with "
       "no version anywhere it is refused (audited) with the step to take, nothing written", got,
       [(202, True, False, "1.21.4"), (202, False, True, None)])


try:
    _update_record282()
    _sftp_staged282()
    _bluemap_threads282()
    _b3_namesake282()
    _b3_reread282()
    _addon_web282()
    _idt3_unread282()
    _push_words282()
    _escaped_values282()
    _root_cron282()
    _dbm_keyless282()
    _server_cases282()
    _restore_signal282()
    _sign_release282()
    _bluemap_version282()
finally:
    _sh282.rmtree(_TMP282, ignore_errors=True)
