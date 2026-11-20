"""Part 276 of the unit suite: runtime fixes of review pass 34.

1. A B3 settings Apply while a new image is pending is refused (the unit would name an image the
   host doesn't have, and B3 would stay down until Update); the card offers Update instead.
2. An SFTP transfer whose permission re-check goes unanswered still asks once a second, not once
   per packet, and an ask that waited past the grace is not let through on the time it began.
3. The root-capable-account verdict is asked once per account at a time and refreshed before it
   expires, so an SFTP burst on a host that answers is never refused by the per-host cap.
4. A remove whose best-effort account release loses the host is still audited and answered
   "removed" (it said the host was unreachable and left no audit row).
5. The remote release's "uid still has a process" test survives a process exiting during the scan
   (it read that as "no process" and deleted a live uid's journal).
6. A game restore over a home whose symlink points at a target the archive lacks keeps the
   archive's copy (it was deleted, leaving a dangling link); a folder link's target that is a file
   undoes the switch.
7. An idTech3 kick or ban by slot acts only while the slot still holds the player named (the slot
   is handed to the next player who joins).
8. A key set twice in a cfg or .properties file is one field in the Settings form, the last line:
   the one the game reads (editing the first said "Saved" and changed nothing the game used).
9. A database table keyed by a binary column is read-only in the editor (its key went back as the
   value's length, so an edit or delete hit no row, or the row whose key was that number).
10. A backup and an uninstall of one server refuse each other (the uninstall killed the backup's
    tar and a "backup failed" alert went out about a server being deleted).
11. Editing a host's name and address with a fingerprint holds no database write lock across the
    fingerprint check's SSH sign-in.
12. The reboot dialog names every kind of work the server reports as blocking (five read only
    "work is running").
13. The root cron page renders for a host whose crontab or a cron.d file is not valid UTF-8 (a 500),
    showing such a line but never offering it for edit.
14. The start port check reads a crossplay Valheim's port + 1, as every other port reader does since
    review pass 33 (up on 2457 only, it was "not listening" and the start went ahead blind).
15. B3's card shows release 2.0.1 (the fork's tag on the pinned commit) and an installed B3 is told
    it is up to date; the image's tag is the commit and build id alone, so the label offers no update.

Nothing here reaches a host.
"""
import os
import base64 as _b64_276
import json as _json276
import sqlite3 as _sql276
import subprocess as _sp276  # nosec B404 - bash over this part's own throwaway files
import tarfile as _tar276
import tempfile as _tf276
import time as _time276
import types as _types276

import eventlet as _ev276
from paramiko import SFTP_FAILURE as _SFTP_FAILURE276, SFTP_OK as _SFTP_OK276

from unit.part01 import eq, skip
from unit.part12 import (P9_ADMIN, P9_HOST, _p9, _p9_arm, _p9_audit, _p9_client, _p9_delete_server, _p9_json,
                         _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all)
from unit.part47 import _cut47
from unit.part190 import _U190, _UNDO190, _Sb190, _crafted190, _missing190
from unit.part219 import _answer219
from unit.part221 import _node221
from panel.core import config as _cfg276
from panel.core.panel_state import r36j_route_job as _job276
from panel.db.models import GameServer as _GS276, RemoteServer as _RS276, db as _db276
from panel.ops.ssh_manager import _core as _core276, db_data as _dd276, game as _game276
from panel.security import privileged as _pv276
from panel.routes import databases_data as _ddr276, manage_servers as _ms276, remotes as _rem276
from panel.routes import _shared as _sh276, addons as _ra276, addons_change as _ch276, server_files as _sfr276
from panel.services import game_restore as _grs276, port_check as _pck276, reboot_words as _rw276
from panel.services import root_cron as _rc276
from panel.services import addons as _ad276, sftp_broker as _br276, sftp_files as _sf276


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. B3 settings wait for a pending image update
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _apply276(sid, image, kind):
    """(why, shells run) for one change of B3 whose record names `image`."""
    shells = []
    probe = {"meta": {"database": "", "port": 0, "image": image, "geolocation": "off"}, "ports": [], "udp": [],
             "ids": (1000, 1000), "logdir": "log", "log_found": True, "log_name": "games_mp.log", "splice": False,
             "rcon_lines": ""}
    _p9_arm(who="part276")
    _p9_patch(_ch276, "_read", lambda gs, addon_id: (dict(probe), "", ""))
    _p9_patch(_ch276, "_geoip_for", lambda *a: "")
    _p9_patch_sm("shell_as_game_user", lambda *a, **k: shells.append(a[2]) or (_ad276._MARK_INSTALLED, "", 0))
    try:
        with _p9.app_context():
            gs = _db276.session.get(_GS276, sid)
            why, _tail = _ch276._change_steps(gs, "b3", "p276", kind, ("off", list(_ad276.B3_PLUGINS), False))
    finally:
        _p9_restore_all()
    return why, len(shells)


def _settings_pending276():
    sid = _p9_new_server(P9_HOST, "cod4p276", "cod4", 28960, name="p276-cod4")
    try:
        new = _ad276.CATALOG["b3"]["image"]
        old = "localhost/lgsm-addon-b3:old-p276"
        got = [_apply276(sid, old, "settings"), _apply276(sid, new, "settings"), _apply276(sid, old, "update")]
        _remove_release_lost276(sid)
        _dup_keys276(sid)
        _backup_uninstall276(sid)
    finally:
        _p9_delete_server(sid)
    eq("add-ons: a B3 settings Apply while a newer image is pending is refused with 'Update first' and runs "
       "nothing on the host (it would write the new image into the unit, never build it, and leave B3 down)",
       got[0], (_ch276._UPDATE_FIRST, 0))
    eq("add-ons: ...with the record on the catalog's image Apply runs, and an Update with the old image runs "
       "(controls)", [w == "" and n == 1 for w, n in got[1:]], [True, True])


def _remove_release_lost276(sid):
    def priv(remote, verb, args, timeout=None, **_k):
        raise ConnectionError("the host closed the connection")
    _p9_arm(who="part276")
    _p9_patch(_ra276, "game_account_write_refusal", lambda *a, **k: None)
    _p9_patch_sm("shell_as_game_user", lambda *a, **k: ("removed=1\nothers=0\nADDON_REMOVED\n", "", 0))
    _p9_patch_sm("run_privileged", priv)
    before = _p9_audit("addon_remove").id
    try:
        r = _p9_client(P9_ADMIN).post("/api/server/%d/addons/b3/remove" % sid)
    finally:
        _p9_restore_all()
    aud = _p9_audit("addon_remove")
    eq("add-ons: a remove done on the host whose best-effort account release then loses the host is audited and "
       "answered 'removed' (it said the host was unreachable, with no audit row), and the job ends",
       (r.status_code, _p9_json(r).get("success"), aud.id != before, aud.success, aud.detail,
        _ra276.job_running(sid)), (200, True, True, True, "b3 removed", False))


def _card276():
    src = open(os.path.join(os.path.dirname(_ch276.__file__), "..", "static", "js", "server_addons.js"),
               encoding="utf-8").read()
    prog = ("var made = [];\n"
            "function node(t, c, x){ if (x) made.push(x); return {appendChild: function(){}, setAttribute: "
            "function(){}, insertBefore: function(){}, lastChild: null}; }\n"
            "function button(label, icon, act){ made.push(act); return {}; }\n"
            "function T(s){ return s; } function TF(s){ return s; } function geoSelect(){ return node(); }\n"
            "function ownPlugins(){} function geoStatus(){} function creditLine(){}\n"
            + _cut47(src, "function updateWords(") + "\nvar BM = {updateWords: updateWords, status: function(){}};\n"
            + _cut47(src, "function settingsFold(") + "\n" + _cut47(src, "function installedRow(") + "\n"
            "function pick(m){ return m === 'adSettings' || m.indexOf('Update the add-on first') === 0"
            " || m.indexOf('Up to date') === 0 || m.indexOf('Update available') === 0; }\n"
            "function acts(a){ made = []; settingsFold(a, node(), node()); return made.filter(pick); }\n"
            "function row(a){ made = []; installedRow(a, node()); return made.filter(pick); }\n"
            "console.log(JSON.stringify({pending: acts({id: 'b3', update: 'image'}),"
            " geoip: acts({id: 'b3', update: 'geoip'}), none: acts({id: 'b3', update: ''}),"
            " current: row({id: 'b3', state: 'active', update: ''}), behind: row({id: 'b3', state: 'active', update: 'image'})}));\n")
    got = _node221("add-ons card: B3 settings with an image update pending", prog)
    if got is not None:
        eq("add-ons card: with a new image pending B3's settings say 'Update the add-on first' in place of Apply; "
           "with a country-database update or none they offer Apply (controls)",
           [got.get(k) for k in ("pending", "geoip", "none")],
           [["Update the add-on first, then apply its settings."], ["adSettings"], ["adSettings"]])
        eq("add-ons card: an installed add-on with no update pending says it is up to date (it said nothing, so a "
           "check could not be told from none); one with an update says that instead (control)",
           [got.get("current"), got.get("behind")],
           [["Up to date (checked just now)."], ["Update available: a newer version of the add-on."]])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. SFTP: an unanswered re-check still counts as the second's check
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _upload276(wait=0.0):
    """(an open upload, the asks it made): every re-check is answered busy after `wait` seconds."""
    ns, asks = _types276.SimpleNamespace, []
    vfs = ns(service=ns(files=ns(cap=1 << 30)), open_count=0, split=lambda p: tuple(p.rsplit("/", 1)))
    info = {"rel": "cfg/b276.cfg", "limit": 1 << 30, "readable": False, "mode": {}}
    wh = _sf276.WriteHandle(vfs, "/P276/cfg/b276.cfg", ns(key=(276,)), None, None, info, stage=bytearray())

    def _ask(folder, write):
        asks.append(folder)
        if wait:
            _time276.sleep(wait)
        raise _sf276.Unanswered(_SFTP_FAILURE276, _br276.HOST_BUSY)
    vfs.ask_folder = _ask
    wh._checked = 0.0
    return wh, asks


def _sftp_rate276():
    wh, asks = _upload276()
    burst = [wh.write(i * 64, b"x" * 64) for i in range(4)]
    eq("sftp busy: an upload whose re-check goes unanswered asks the panel once for a burst of writes within a "
       "second, not once per packet (each ask took a slot from the pool that was already short)",
       (burst, len(asks)), ([_SFTP_OK276] * 4, 1))
    wh, asks = _upload276(wait=0.2)
    wh._granted = _time276.monotonic() - _sf276.AUTHZ_GRACE + 0.1
    eq("sftp busy: an ask that waited past the grace after the last yes refuses the write with the busy reason "
       "(the grace was judged on the time the ask began)", wh.write(0, b"x"), (_SFTP_FAILURE276, _br276.HOST_BUSY))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. One account probe at a time, refreshed ahead of its expiry
# ════════════════════════════════════════════════════════════════════════════════════════════════
_REMOTE276 = _types276.SimpleNamespace(id=276001, host="198.51.100.76", username="p276")
_KEY276 = (276001, "198.51.100.76", "p276", "vh276")


def _burst276(n, call):
    """[what each of `n` concurrent calls returned, in the order they ended], probes made, peak host count."""
    probes, ended, peak = [], [], [0]

    def probe(remote, users):
        probes.append(users)
        peak[0] = max(peak[0], _br276._HOST_ASKS.get(276001, 0))
        _ev276.sleep(0.05)
        return {}
    _p9_patch(_sh276, "privileged_accounts", probe)
    try:
        pool = [_ev276.spawn(lambda i=i: ended.append((i, call()))) for i in range(n)]
        for g in pool:
            g.wait()
    finally:
        _p9_restore_all()
    return ended, len(probes), peak[0]


def _verdict_flight276():
    with _sh276._ACCOUNT_VERDICTS_LOCK:
        _sh276._ACCOUNT_VERDICTS.pop(_KEY276, None)
    cold = _burst276(3, lambda: _sh276.game_account_write_refusal(_REMOTE276, "vh276"))
    eq("account verdict: three writes that find no verdict at the same time ask the host once, and all three get "
       "its answer", ([r for _i, r in cold[0]], cold[1]), ([None, None, None], 1))
    with _sh276._ACCOUNT_VERDICTS_LOCK:
        _sh276._ACCOUNT_VERDICTS[_KEY276] = (_time276.monotonic() + _sh276._ACCOUNT_REFRESH_AHEAD / 2, "")
    late = _burst276(3, lambda: _sh276.game_account_write_refusal(_REMOTE276, "vh276"))
    with _sh276._ACCOUNT_VERDICTS_LOCK:
        left = _sh276._ACCOUNT_VERDICTS[_KEY276][0] - _time276.monotonic()
    eq("account verdict: a verdict in its last seconds is refreshed by one caller while the others read it at "
       "once (they end first), and the new one runs a full minute", ([i for i, _r in late[0]], late[1],
                                                                       left > _sh276._ACCOUNT_REFRESH_AHEAD),
       ([1, 2, 0], 1, True))


def _authz_burst276():
    gs = _types276.SimpleNamespace(remote_id=276001, id=276, remote=_REMOTE276, short_name="vh276")
    _p9_patch(_br276, "_session_user", lambda req: (_types276.SimpleNamespace(is_superadmin=True), None))
    _p9_patch(_br276, "editable", lambda user: {"vh": gs})
    _p9_patch(_br276, "describe", lambda g: {"sid": g.id})
    with _sh276._ACCOUNT_VERDICTS_LOCK:
        _sh276._ACCOUNT_VERDICTS[_KEY276] = (_time276.monotonic() + 1, "")
    got = _burst276(_br276.HOST_SLOTS + 2, lambda: _br276._h_authz(_p9, {"folder": "vh", "write": False}, None))
    with _sh276._ACCOUNT_VERDICTS_LOCK:
        _sh276._ACCOUNT_VERDICTS.pop(_KEY276, None)
    eq("sftp busy: more open files than the per-host cap re-checking as the account verdict runs out on a host "
       "that answers: none is answered busy, and the host is asked once",
       (sorted(str(r) for _i, r in got[0]), got[1], got[2]), (["{'ok': True, 'sid': 276}"] * (_br276.HOST_SLOTS + 2),
                                                              1, 1))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. The remote release's process test and a process that exits during it
# ════════════════════════════════════════════════════════════════════════════════════════════════
_EMPTY276 = b"LPKSHHRH" + b"\0" * 160


def _forget_left276(live):
    """The journals left after a remote "forget" when a pid exits mid-scan; `live`: uid 5004 still runs."""
    with _tf276.TemporaryDirectory(prefix="p276j-") as base:
        mid = os.path.join(base, "var", "0123456789abcdef0123456789abcdef")
        os.makedirs(mid)
        os.makedirs(os.path.join(base, "run"))
        os.makedirs(os.path.join(base, "proc", "4241"))
        os.symlink(os.path.join(base, "exited"), os.path.join(base, "proc", "4241", "status"))
        if live:
            os.makedirs(os.path.join(base, "proc", "4242"))
            with open(os.path.join(base, "proc", "4242", "status"), "w", encoding="ascii") as fh:
                fh.write("Name:\tx\nUid:\t5004\t5004\t5004\t5004\n")
        for name in ("user-5000.journal", "user-5004.journal"):     # the account's own makes it rotate
            with open(os.path.join(mid, name), "wb") as fh:
                fh.write(_EMPTY276)
        sh = (_pv276._addon_release_remote(["cod4server", "forget"]).replace("/var/log/journal", base + "/var")
              .replace("/run/log/journal", base + "/run").replace("/proc/", base + "/proc/"))
        stubs = ('id() { echo 5000; }; loginctl() { :; }; systemctl() { :; }; timeout() { shift; "$@"; }; '
                 'journalctl() { :; }; getent() { return 1; }; ')
        # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit.dangerous-subprocess-use-audit
        _sp276.run(["bash", "-c", stubs + sh], capture_output=True, text=True, timeout=30, check=False,  # nosec B603 B607
                   env={"PATH": "/usr/bin:/bin"})
        return sorted(os.listdir(mid))


def _forget_live276():
    eq("remote release (bash): a process that exits during the scan does not hide another process of the uid, so "
       "that uid's live journal stays; with no process of the uid it goes (control)",
       (_forget_left276(True), _forget_left276(False)), (["user-5004.journal"], []))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 6. A game restore and a symlink whose target the archive lacks
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _relink_case276(members, links):
    """Restore an archive of `members` over the stand-in home with `links` {path: target} added: (state, home)."""
    sb = _Sb190()
    try:
        for path, target in links.items():
            full = os.path.join(sb.home, path)
            if target.endswith("/"):
                os.makedirs(os.path.join(os.path.dirname(full), target), exist_ok=True)
            else:
                sb.put(os.path.join(os.path.dirname(path), target), "current")
            os.symlink(target.rstrip("/"), full)
        name = _crafted190(sb, members)
        ready = sb.vet(name)[1][1]
        with open(os.path.join(sb.bdir, _UNDO190), "wb") as f:
            f.write(b"undo")
        out, rc = sb.run(_grs276.restore_script(_U190, _U190, name, ready["t0"], ready["need"], _UNDO190,
                                                busy_polls=1, members=ready["members"]))
        seen = {p: ("link to " + os.readlink(os.path.join(sb.home, p)) if os.path.islink(os.path.join(sb.home, p))
                    else sb.read(p) is not None) for p in ("serverfiles/wl", "serverfiles/saves/w/level.dat",
                                                           "serverfiles/cl", "serverfiles/real.cfg")}
        return _grs276.restore_outcome(out, rc)[0], seen
    finally:
        sb.gone()


def _relink276():
    if _missing190:
        skip("game restore: a link whose target the archive lacks keeps the archive's copy",
             "missing tools: %s" % _missing190)
        return
    reg, dirt = _tar276.REGTYPE, _tar276.DIRTYPE
    got = _relink_case276([("././serverfiles/", dirt, ""), ("././serverfiles/wl/", dirt, ""),
                           ("././serverfiles/wl/level.dat", reg, ""), ("././serverfiles/cl", reg, "")],
                          {"serverfiles/wl": "saves/w/", "serverfiles/cl": "real.cfg"})
    eq("game restore: a folder link and a file link whose targets the archive does not hold get the archive's copy "
       "moved to the target and the link made again (the copy was deleted and the link left dangling)",
       got, ("done", {"serverfiles/wl": "link to saves/w", "serverfiles/saves/w/level.dat": True,
                      "serverfiles/cl": "link to real.cfg", "serverfiles/real.cfg": True}))
    got = _relink_case276([("././serverfiles/", dirt, ""), ("././serverfiles/wl/", dirt, ""),
                           ("././serverfiles/wl/level.dat", reg, ""), ("././serverfiles/saves/", dirt, ""),
                           ("././serverfiles/saves/w", reg, "")], {"serverfiles/wl": "saves/w/"})
    eq("game restore: ...a folder link whose target is a file in the archive undoes the switch (nothing changed)",
       got[0], "refused")


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 7. idTech3: a slot that changed hands
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _slot_case276(listed, action, target):
    """(moderate's answer, the console lines it sent) with `listed` as the console's player list now."""
    sent = []
    _p9_patch(_core276, "send_console_command", lambda server, user, cmd, **k: sent.append(cmd) or ("", "", 0))
    _p9_patch(_game276, "console_player_list", lambda *a, **k: listed)
    try:
        return _game276.moderate(None, "u276", "cod4", action, target=target, num="3"), sent
    finally:
        _p9_restore_all()


def _idt3_slot276():
    moved = [_slot_case276([{"name": "Innocent", "num": 3}, {"name": "Griefer", "num": 5}], a, "Griefer")
             for a in ("kick", "ban")]
    eq("moderation (idTech3): a Kick or Ban posted for slot 3 and 'Griefer' while slot 3 now holds someone else "
       "is refused and sends nothing (it kicked or banned whoever took the slot)",
       moved, [((False, _game276.IDT3_SLOT_MOVED), [])] * 2)
    held = [_slot_case276([{"name": "^1Griefer", "num": 3}], "ban", "Griefer"),
            _slot_case276([{"name": "Innocent", "num": 3}], "kick", "")]
    eq("moderation (idTech3): ...with the player still in the slot (colours read as on screen) the ban is sent, and "
       "a slot with no name is sent as before (controls)",
       held, [((True, "Done."), ["banclient 3"]), ((True, "Done."), ["clientkick 3"])])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 8. A key set twice: the form edits the line the game reads
# ════════════════════════════════════════════════════════════════════════════════════════════════
_CFG276 = 'hostname "p276"\n// RCON\nrcon_password "first"\nsv_cheats 0\n// appended later\nRCON_PASSWORD "last"\n'
_UT276 = "[Engine.GameEngine]\nServerPackages=A\nServerPackages=B\n"


def _form_fields276(form):
    return [(f["key"], f["value"], f["id"]) for g in (form or {}).get("groups", []) for f in g["fields"]]


def _dup_keys276(sid):
    files, writes = {"serverfiles/cfg/p276.cfg": _CFG276, "serverfiles/System/p276.ini": _UT276}, []
    _p9_arm(who="part276")
    _p9_patch_sm("read_file", lambda server, user, rel, **k: (files[rel], None))
    _p9_patch_sm("write_file", lambda server, user, rel, content, **k: writes.append(content) or (True, ""))
    _p9_patch(_sfr276, "_read_refused", lambda *a, **k: None)
    _p9_patch(_sfr276, "_write_refused", lambda *a, **k: None)
    c, url = _p9_client(P9_ADMIN), "/api/server/%d/game-config/form" % sid
    try:
        got = _p9_json(c.get(url + "?path=serverfiles/cfg/p276.cfg"))
        fields = _form_fields276(got.get("form"))
        rid = [i for k, _v, i in fields if k.lower() == "rcon_password"]
        saved = _p9_json(c.post(url, json={"path": "serverfiles/cfg/p276.cfg", "hash": got["form"]["hash"],
                                           "changes": {str(rid[0]): "rotated"}})) if rid else {}
        ini = _form_fields276(_p9_json(c.get(url + "?path=serverfiles/System/p276.ini")).get("form"))
    finally:
        _p9_restore_all()
    eq("config form: an RCON password set twice in a cfg (any case) is one field holding the last value, and "
       "saving it changes the last line, the one the game reads (the first was edited and the old one stayed live)",
       ([(k, v) for k, v, _i in fields], saved.get("success"), writes[-1:]),
       ([("hostname", "p276"), ("sv_cheats", "0"), ("RCON_PASSWORD", "last")], True,
        [_CFG276.replace('"last"', '"rotated"')]))
    eq("config form: ...an .ini keeps every line of a repeated key (Unreal reads them as an array) (control)",
       [(k, v) for k, v, _i in ini], [("ServerPackages", "A"), ("ServerPackages", "B")])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 9. A binary primary key is read-only in the database editor
# ════════════════════════════════════════════════════════════════════════════════════════════════
_BIN_ANS276 = _answer219(
    ([(["TABLE_NAME", "TABLE_TYPE", "ENGINE", "TABLE_ROWS", "S"],
       [["uuids", "BASE TABLE", "InnoDB", "3", "16384"], ["named", "BASE TABLE", "InnoDB", "3", "16384"]])], -1),
    ([(["TABLE_NAME", "COLUMN_NAME", "COLUMN_TYPE", "DATA_TYPE", "IS_NULLABLE", "COLUMN_KEY", "COLUMN_DEFAULT",
        "EXTRA", "CS", "CO"],
       [["named", "id", "varchar(16)", "varchar", "NO", "PRI", None, "", "utf8mb4", "utf8mb4_unicode_ci"],
        ["named", "v", "int(11)", "int", "YES", "", None, "", None, None],
        ["uuids", "id", "binary(16)", "binary", "NO", "PRI", None, "", None, None],
        ["uuids", "v", "int(11)", "int", "YES", "", None, "", None, None]])], -1),
    ([(["TABLE_NAME", "COLUMN_NAME"], [["named", "id"], ["uuids", "id"]])], -1))


def _binary_key276():
    tables = _dd276.structure(_dd276.parse(_BIN_ANS276))
    _p9_patch(_ddr276, "_structure", lambda gs, r, fresh=False: (tables, None))
    try:
        with _p9.test_request_context("/"):
            got = []
            for name in ("uuids", "named"):
                t, refused = _ddr276._keyed_table(None, None, {"table": name})
                got.append((t is None, refused[0].get_json().get("message") if refused else None))
    finally:
        _p9_restore_all()
    eq("database editor: a table keyed by a BINARY(16) column is read-only (an edit or delete is refused with why, "
       "and its page sends no key); a text key stays editable (control)",
       (got, _dd276.rows_statement(tables["uuids"], 0)["sql"].count("ORDER BY")),
       ([(True, _ddr276.S_READONLY["binary_key"]), (False, None)], 0))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 10. A backup and an uninstall refuse each other
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _backup_uninstall276(sid):
    ran, uninstalled = [], []
    _p9_arm(who="part276")
    _p9_patch(_ms276, "_r25b_uninstall_claimed", lambda app, gs, remote, server_id, name:
              uninstalled.append(server_id) or _ms276._index_reply("x", True, "success"))
    c = _p9_client(P9_ADMIN)
    try:
        with _job276(sid, "uninstall"):
            marked = _sh276._marked_backup(sid, None, None, runner=lambda *a, **k: ran.append(a) or (True, "", False))
            left = sid in _sh276._game_backup_status
            now = c.post("/api/panel/backup/game/%d" % sid, json={}).status_code
        _sh276._game_backup_status[sid] = {"running": True, "ok": None, "msg": "", "ts": 0}
        removing = c.post("/servers/%d/delete" % sid, headers={"X-Requested-With": "XMLHttpRequest"}).status_code
    finally:
        _sh276._game_backup_status.pop(sid, None)
        _p9_restore_all()
    eq("backup vs uninstall: while the server is being uninstalled a scheduled backup is skipped (nothing run, no "
       "mark left) and Back up now is refused (409); while it is being backed up the uninstall is refused (409) "
       "and removes nothing",
       (marked, ran, left, now, removing, uninstalled), ((False, _sh276._R39A_BACKUP_HELD, True), [], False, 409, 409, []))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 11. A host edit holds no write lock across its SSH check
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _locked276():
    """Whether another connection is kept out of writing the suite's database right now."""
    path = _p9.config["SQLALCHEMY_DATABASE_URI"][len("sqlite:///"):]
    other = _sql276.connect(path, timeout=0)
    try:
        other.execute("BEGIN IMMEDIATE")
        other.rollback()
        return False
    except _sql276.OperationalError:
        return True
    finally:
        other.close()


def _edit_lock276():
    with _p9.app_context():
        row = _RS276(name="p276-host", host="192.0.2.76", port=22, username="root", auth_method="key")
        _db276.session.add(row)
        _db276.session.commit()
        rid = row.id
    seen = []

    def ssh(*a, **k):
        seen.append(_locked276())
        return False, "stub"
    _p9_arm(who="part276")
    _p9_patch(_rem276, "ssh_test_connection", ssh)
    try:
        r = _p9_client(P9_ADMIN).post("/remotes/%d/edit" % rid, headers={"X-Requested-With": "XMLHttpRequest"}, data={
            "name": "p276-renamed", "host": "192.0.2.77", "ssh_user": "root", "ssh_port": "22", "auth_method": "key",
            "credential": "", "host_key_fingerprint": "SHA256:" + "A" * 43})
    finally:
        _p9_restore_all()
        with _p9.app_context():
            name = _db276.session.get(_RS276, rid).name
            _db276.session.delete(_db276.session.get(_RS276, rid))
            _db276.session.commit()
    eq("host edit: a new name and address with a fingerprint run the fingerprint's SSH check with no database write "
       "lock held (other writers waited on it), and the refused edit keeps the old name",
       (seen, r.status_code, name), ([False], 400, "p276-host"))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 12. The reboot dialog's phrase for every blocker kind
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _nags276():
    src = open(os.path.join(os.path.dirname(_ch276.__file__), "..", "static", "js", "nags.js"), encoding="utf-8").read()
    kinds = sorted(_rw276._BLOCKER_WORDS)
    prog = ("function El(tag){ this.tag = tag; this.children = []; }\n"
            "El.prototype.setAttribute = function(){};\n"
            "El.prototype.appendChild = function(c){ this.children.push(c); return c; };\n"
            "global.document = {createElement: t => new El(t), createTextNode: t => ({text: t})};\n"
            + "\n".join(_cut47(src, h) for h in ("function _rbEl", "function _rbName", "function _rbRow",
                                                   "function _rbBlockersList"))
            + "\nconst ul = _rbBlockersList({blockers: %s});\n" % _json276.dumps([{"kind": k, "name": k} for k in kinds])
            + "console.log(JSON.stringify(ul.children.map(li => li.children[2].textContent)));\n")
    got = _node221("reboot dialog: every blocker kind", prog)
    if got is not None:
        eq("reboot dialog: every kind of work the server names as blocking a reboot (mods, scheduled tasks, wipes, "
           "queued stops, add-on jobs among them) has its own phrase, none the bare 'work is running'",
           [k for k, said in zip(kinds, got) if said == "work is running"], [])


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 13. The root cron page and bytes that are not UTF-8
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _root_cron_latin1_276():
    crontab = b"# caf\xe9 au lait\n0 1 * * * /p276/run \xe9t\xe9\n30 2 * * * /p276/ok\n"
    crond = b"# r\xe9sum\xe9\n"

    def priv(server, verb, args=(), **_kw):
        return ("root-crontab ok %s\ncrond p276 %s\n" % (_b64_276.b64encode(crontab).decode(),
                                                         _b64_276.b64encode(crond).decode()), "", 0)
    was = _cfg276.load_config().get(_rc276.ENABLED_KEY)
    _cfg276.update_config(lambda cfg: cfg.update({_rc276.ENABLED_KEY: True}))
    _p9_arm(who="part276")
    _p9_patch(_core276, "run_privileged", priv)
    _p9_patch(_core276, "helper_present", lambda recheck=False: True)
    _p9_patch(_rc276, "host_opened", lambda is_local, helper: True)
    try:
        r = _p9_client(P9_ADMIN).get("/root-cron/%d" % P9_HOST)
        page = r.get_data(as_text=True)
    finally:
        _p9_restore_all()
        _cfg276.update_config(lambda cfg: cfg.update({_rc276.ENABLED_KEY: was}))
    kinds = [(row["kind"], row["raw"]) for row in _rc276.rows(_rc276.parse_read(priv(None, "")[0])["text"])]
    eq("root cron page: a crontab and a cron.d file holding Latin-1 bytes render (they made the page a 500), each "
       "such byte shown as U+FFFD; the job line holding one is shown, never offered for edit, and the plain job "
       "still is", (r.status_code, "caf\ufffd au lait" in page, "r\ufffdsum\ufffd" in page, 'value="30 2 * * * /p276/ok"'
                    in page, 'value="0 1 * * * /p276/run' in page, kinds[1]),
       (200, True, True, True, False, ("other", "0 1 * * * /p276/run \ufffdt\ufffd")))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 14. The start port check and Valheim's port + 1
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _port_said276(sid, live):
    """start_refusal for server `sid` with `live` listening: (its template or None, its port)."""
    _p9_patch_sm("_remote_listening_ports", lambda remote: set(live))
    _p9_patch_sm("server_live_metrics", lambda *a, **k: {"ram_total": 1, "game_procs": 1})
    try:
        with _p9.app_context():
            gs = _db276.session.get(_GS276, sid)
            got = _pck276.start_refusal(gs, gs.remote)
    finally:
        _p9_restore_all()
    return (got.template, got.vals.get("port")) if got is not None else (None, None)


def _valheim_port276():
    vh = _p9_new_server(P9_HOST, "vh276", "vh", 24760, status="offline")
    gm = _p9_new_server(P9_HOST, "gm276", "gmod", 27660, status="offline")
    other = None
    try:
        up = _port_said276(vh, {24761})
        plain = _port_said276(gm, {27661})
        other = _p9_new_server(P9_HOST, "vh276b", "vh", 24759, status="online", name="p276-vh-b")
        claimed = _port_said276(vh, set())
    finally:
        for sid in (vh, gm, other):
            if sid is not None:
                _p9_delete_server(sid)
    eq("port check: a Valheim up on its port + 1 only (crossplay) is seen before a start ('may already be up'), and "
       "another running Valheim whose port + 1 is this server's port is named; another game's port + 1 is not its "
       "own (control)", (up[1], "may already be up" in (up[0] or ""), claimed[1], plain), (24761, True, 24760, (None, None)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 15. B3's release label, and an image tag it does not change
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _b3_release276():
    b3 = _ad276.CATALOG["b3"]
    tag = "localhost/lgsm-addon-b3:%s-%s" % (_ad276.B3_COMMIT[:12], _ad276.build_id(
        os.path.join(os.path.dirname(_ad276.__file__), "..", "addon_images", "b3"), _ad276.B3_BASE))
    eq("B3: the card names release 2.0.1 with the pinned commit, and the image's tag is the commit and the build id "
       "alone (a new release label offers installed B3s no update)",
       (b3["version"], b3["image"] == tag, _ad276.B3_RELEASE in b3["image"]), ("2.0.1 (920d7366)", True, False))


_settings_pending276()
_card276()
_sftp_rate276()
_verdict_flight276()
_authz_burst276()
_forget_live276()
_relink276()
_idt3_slot276()
_binary_key276()
_edit_lock276()
_nags276()
_root_cron_latin1_276()
_valheim_port276()
_b3_release276()
