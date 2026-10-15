"""Part 74 of the unit suite: the eighth review's fixes (review 1012c, builder B).

Game files, the debug report, the privileged helper and routes:

* Kick/Ban by name: a Source/GoldSrc name resolves only to the same name (the colour-code
  stripping meant for idTech3 made a departed "Bob" resolve to a connected "^_^ Bob", whose SteamID
  a fleet-wide ban then took), and an idTech3 name two console rows share on screen resolves to no
  one (the exact one was taken first).

* A console line holding a control character is refused in the viewer's language by the custom
  command route and by moderation (it read as the host failing, or "Console not reachable").

* An IPv6 host is bracketed in the chat bots' `!connect` reply and on the host page's server list.

* Debug report: a known dotted name of 28+ characters, alone or with a URL path, prints as its
  token rather than [redacted]; an IP-ageing cutoff before year 1000 is zero-padded.

* restart-flags: a home root cannot look in is named (`?<name>`), on the panel host and on remotes,
  and only that account's banner is left as it was; the others are applied.

HOW IT RUNS. On part12's Flask app and stubs, as part71 does; nothing reaches a transport. The
remote restart-flags form runs in a real bash on a scratch tree.
"""
import base64 as _b64_74
import contextlib as _ctx74
import io as _io74
import os
import shutil as _shutil74
import sqlite3 as _sqlite74
import subprocess as _sp74  # nosec B404 - runs bash on the restart-flags command this repo builds
import tempfile as _tf74
from types import SimpleNamespace as NS

from unit.part01 import _R20dOver, check
from unit.part05 import _helper
from unit.part12 import (_P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_core, _p9_json, _p9_patch,
                         _p9_restore_all, _p9_sd, _p9_trip)
from flask import session as _session74
from panel.core import i18n as _i18n74
from panel.db.models import AuditLog, CustomCommand, GameServer, RemoteServer, User, db
from panel.ops.debug_report import data as _data74, privacy as _pv74
from panel.ops.debug_report._base import Ctx as _Ctx74
from panel.ops.ssh_manager import game as _game74
from panel.security import auth as _auth74, privileged as _priv74
from panel.services import monitoring as _mon74
from panel.services.bots import commands as _cmds74

_TRIP74_START = len(_P9_TRIPPED)
_mine74 = {"hosts": [], "servers": [], "users": [], "cmds": []}
_TMP74 = os.path.realpath(_tf74.mkdtemp(prefix="lgsm-unit-p74-"))
_V6_74 = "2001:db8::74"
_CONTROL_ES74 = "Un comando de consola no puede contener caracteres de control ni saltos de línea."


def _arm74():
    # part12's shared tripwire (every transport, system_ops' handles, the modules' own subprocess),
    # plus the three _core senders this part's checks stub one at a time.
    _p9_arm(who="part74")
    _p9_patch(_p9_core, "run_command", _p9_trip("run_command"))
    _p9_patch(_p9_core, "shell_as_game_user", _p9_trip("shell_as_game_user"))
    _p9_patch(_p9_core, "run_privileged", _p9_trip("run_privileged"))


def _setup74():
    with _p9.app_context():
        r = RemoteServer(name="p74-host", host=_V6_74, port=22, username="admin",
                         auth_method="key", auth_credential="", is_online=True)
        db.session.add(r)
        db.session.commit()
        gs = GameServer(remote_id=r.id, name="p74-css", short_name="p74css", game_type="css",
                        port=27074, installed=True, status="online")
        admin = User(username="p74_admin", password_hash=_auth74.hash_password("Str0ng!passw0rd-p74"),
                     display_name="p74 admin", is_superadmin=True, is_active=True)
        cmd = CustomCommand(name="p74say", command_template="say {}", argument_label="",
                            argument_pattern="^.{1,100}$", scope_type="all", enabled=True)
        db.session.add_all([gs, admin, cmd])
        db.session.commit()
        _mine74["hosts"].append(r.id)
        _mine74["servers"].append(gs.id)
        _mine74["users"].append(admin.id)
        _mine74["cmds"].append(cmd.id)
        return r.id, gs.id, admin.id, cmd.id


def _cleanup74():
    with _p9.app_context():
        for i in _mine74["servers"]:
            AuditLog.query.filter_by(game_server_id=i).delete()
        AuditLog.query.filter(AuditLog.username.like("p74%")).delete(synchronize_session=False)
        db.session.commit()
        for model, key in ((CustomCommand, "cmds"), (GameServer, "servers"), (User, "users"),
                           (RemoteServer, "hosts")):
            for i in _mine74[key]:
                row = db.session.get(model, i)
                if row is not None:
                    db.session.delete(row)
            db.session.commit()
    for sid in _mine74["servers"]:
        _mon74._cron_restart_pending.pop(sid, None)
    _shutil74.rmtree(_TMP74, ignore_errors=True)


def _as_lang74(lang, call):
    """`call()` with the admin's UI language set to `lang`, then English again."""
    def _set(lg):
        with _p9.app_context():
            db.session.get(User, _ADMIN74).language = lg
            db.session.commit()
    _set(lang)
    try:
        return call()
    finally:
        _set("en")


def _in_lang74(lang, call):
    """`call()` inside a request whose viewer chose `lang` (the session's choice)."""
    with _p9.test_request_context("/"):
        _session74["lang"] = lang
        return call()


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. Kick/Ban by name: which console row a name on screen means
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _resolve74(game_type, name, listed):
    _p9_patch(_game74, "console_player_list", lambda *a, _l=listed, **k: list(_l))
    hit = _game74._resolve_from_console(None, "p74u", game_type, name, None)
    return None if hit is None else (hit.get("steamid") or hit.get("num"))


def _names74():
    v = {"wide": _resolve74("css", "Bob", [{"name": "^_^ Bob", "steamid": "STEAM_0:1:42"}]),
         "narrow": _resolve74("css", "Bob", [{"name": "^1Bob", "steamid": "STEAM_0:1:43"}]),
         "same": _resolve74("css", "Bob", [{"name": "^1Bob", "steamid": "STEAM_0:1:43"},
                                           {"name": "Bob", "steamid": "STEAM_0:1:44"}]),
         "coded": _resolve74("css", "^1Bob", [{"name": "^1Bob", "steamid": "STEAM_0:1:43"},
                                              {"name": "Bob", "steamid": "STEAM_0:1:44"}])}
    check("moderation (Valve): a Ban by name on a player who has left does not resolve to another "
          "player whose name differs by `^x` pairs (gamedig's valve protocol strips nothing, so the "
          "wide match could only find someone else, and the ban went fleet-wide on THEIR SteamID)",
          v["wide"] is None and v["narrow"] is None, repr(v))
    check("moderation (Valve): ...while a connected player is still found by the name the console "
          "shows, codes and all (controls)",
          v["same"] == "STEAM_0:1:44" and v["coded"] == "STEAM_0:1:43", repr(v))
    _p9_patch(_game74, "console_player_list",
              lambda *a, **k: [{"name": "^_^ Bob", "steamid": "STEAM_0:1:42"}])
    gs = NS(game_type="css", remote=None, short_name="p74u", lgsm_name=None)
    pre = _p9_sd._preresolve_ban_steamid(gs, "Bob", "")
    check("moderation (Valve): ...and the ban route's own pre-resolve leaves the SteamID empty for it, "
          "so nothing is fanned out", pre == "", repr(pre))
    # The idTech3 console list is already `^digit`-stripped by its parser, as these rows are.
    q = {"plain+a": _resolve74("q3", "Bob", [{"num": 1, "name": "Bob"}, {"num": 2, "name": "^aBob"}]),
         "only a": _resolve74("q3", "Bob", [{"num": 2, "name": "^aBob^7"}, {"num": 3, "name": "Al"}]),
         "console": _resolve74("q3", "^aBob", [{"num": 1, "name": "Bob"}, {"num": 2, "name": "^aBob"}]),
         "twice": _resolve74("rtcw", "Bob", [{"num": 1, "name": "Bob"}, {"num": 4, "name": "Bob"}])}
    check("moderation (idTech3): a name gamedig shows as \"Bob\" for both \"Bob\" and \"^aBob\" resolves "
          "to no one — the exact row was taken first, so a Kick or an rtcw address ban aimed at "
          "\"^aBob\" landed on the plain \"Bob\" — and nor does a name two rows share",
          q["plain+a"] is None and q["twice"] is None, repr(q))
    check("moderation (idTech3): ...a lone `^a` name is still found, and a name that still holds its "
          "code (it came from the console list) finds exactly its row (controls)",
          q["only a"] == 2 and q["console"] == 2, repr(q))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. A control character in a console line: refused, in the viewer's language
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _control74(client, sid, cid):
    sent = []

    def _send(*a, **k):
        sent.append(a)
        return "", "", 0
    _p9_patch(_p9_sd, "send_console_command", _send)
    _p9_patch(_p9_core, "send_console_command", _send)
    resp = _as_lang74("es", lambda: client.post("/api/server/%d/custom-command/%d" % (sid, cid),
                                                json={"value": "hola\tmundo"}))
    d = _p9_json(resp)
    with _p9.app_context():
        rows = [a.detail for a in AuditLog.query.filter_by(game_server_id=sid,
                                                          action="custom_command").all()]
    check("custom command (es viewer): a value a permissive stored pattern lets through with a TAB is "
          "refused before any send, in Spanish, as a 400 — it was the HOST failing, in English, a "
          "502, with the raw bytes in the audit row",
          resp.status_code == 400 and d.get("message") == _CONTROL_ES74 and not sent
          and not any("\t" in (r or "") for r in rows), repr((resp.status_code, d, sent, rows)))
    d = _p9_json(_as_lang74("es", lambda: client.post("/api/server/%d/custom-command/%d" % (sid, cid),
                                                      json={"value": "hola"})))
    check("custom command: ...a plain value still runs (control)",
          d.get("success") is True and len(sent) == 1, repr((d, sent)))
    del sent[:]
    _control_mod74(sent)


def _control_mod74(sent):
    # Integration note (review 1012c): builder A's fix drops an announcement's control characters
    # in _mod_say_cmd and refuses a player name holding one in words of its own (part73), so no
    # line moderate() builds holds one any more. This part's guard in _r16b_send_moderation stays as
    # the backstop for a builder added later, and is driven directly.
    ok, msg = _game74.moderate(None, "p74u", "css", "say", message="hi\x1b[2J")
    check("moderation: an announcement holding an ESC is sent without it — it read \"Console not "
          "reachable — is the server running?\"",
          ok is True and msg == "Done." and [x[2] for x in sent] == ["say hi[2J"], repr((ok, msg, sent)))
    del sent[:]
    ok, msg = _game74._r16b_send_moderation(None, "p74u", "say hi\x1b[2J", "p74srv", "css", "say")
    es = _in_lang74("es", lambda: _i18n74.tr(msg))
    check("moderation (es viewer): a console line still holding a control byte at the send is refused as "
          "such, in Spanish, and nothing is sent (the backstop behind each command builder)",
          ok is False and es == _CONTROL_ES74 and not sent, repr((ok, msg, es, sent)))
    ok2, msg2 = _game74.moderate(None, "p74u", "css", "say", message="hello")
    check("moderation: ...a plain announcement is still sent (control)",
          ok2 is True and msg2 == "Done." and len(sent) == 1, repr((ok2, msg2, sent)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. An IPv6 host, bracketed wherever players are handed the address
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _ipv6_74(client, rid):
    txt = _cmds74._connect_text(_p9, "p74css")
    want = "[%s]:27074" % _V6_74
    check("chat bots: !connect brackets an IPv6 host (the reply's address line read "
          "\"2001:db8::74:27074\" while the steam:// line under it was bracketed)",
          txt.splitlines()[1:2] == [want] and "steam://connect/" + want in txt, repr(txt))
    html = client.get("/remote/%d/manage" % rid).get_data(as_text=True)
    check("host page: the server list's copyable address and the Join link's address bracket it too",
          'data-copy="%s"' % want in html and 'data-addr="%s"' % want in html
          and "%s:27074" % _V6_74 not in html.replace(want, ""), repr(html.count(want)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. Debug report: a long dotted name keeps its token; a pre-1000 cutoff is zero-padded
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _privacy74():
    st = _pv74._State()
    host, ts = "game-01.eu-west.example-hosting.net", "myhost.tail4a2b3c.ts.net"
    st.add(host, "host", 1)
    st.add(ts, "tailnet-name", 1)
    st.add("alice.smith", "account", 1)
    ctx = _Ctx74()
    ctx._memo["privacy"] = (True, st)
    # Built at run time: a base64-shaped literal here trips Gitleaks' generic-api-key rule.
    tok = _b64_74.b64encode(b"CharlieBrown" + b"xyzfoo").decode()
    text = ("ssh to %s failed\nServe https://%s/lgsm/server/12 ok\n"
            "x %s-%s y\npath %s/a-alice.smith-%s z" % (host, ts, tok, host, host, tok))
    out = _pv74.scrub(ctx, text)
    lines = out.splitlines()
    check("debug report privacy: a known dotted name of 28+ characters prints as its token, alone "
          "and with a URL path after it (both printed [redacted], so a line no longer said which "
          "host it was about)",
          lines[0] == "ssh to [host-1] failed"
          and lines[1] == "Serve https://[tailnet-name-1]/lgsm/server/12 ok", out)
    check("debug report privacy: ...while a secret glued to the name by '-', and a path that holds "
          "another name, are still redacted whole (controls)",
          tok not in out and lines[2] == "x [redacted] y" and lines[3] == "path [redacted] z", out)


def _cutoff74():
    cut = _data74._census_queries(500000)["audit_ips"][1][0]
    con = _sqlite74.connect(":memory:")
    try:
        con.execute("CREATE TABLE audit_log (timestamp TEXT, ip_address TEXT)")
        con.execute("INSERT INTO audit_log VALUES ('2026-10-01 00:00:00', '192.0.2.74')")
        n = con.execute(_data74._IPS_SQL, (cut,)).fetchone()[0]
    finally:
        con.close()
    near = _data74._census_queries(90)["audit_ips"][1][0]
    check("debug report: an audit_ip_retention_days whose cutoff falls before year 1000 is zero-padded "
          "('0657-…'), so a row from this year is not counted as \"older, not reduced\" ('657-…' sorted "
          "after '2026-…', and every row was)",
          cut.startswith("0") and len(cut) == 19 and n == 0, repr((cut, n)))
    check("debug report: ...and a normal value's cutoff still has the same shape (control)",
          len(near) == 19 and near[:2] == "20" and near[10] == " ", repr(near))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. restart-flags: one home root cannot look in costs only that account's answer
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _homes74():
    root = os.path.join(_TMP74, "home")
    for acct, flag in (("flagged", True), ("clear", False), ("locked", False)):
        os.makedirs(os.path.join(root, acct))
        if flag:
            open(os.path.join(root, acct, ".restart-pending"), "w", encoding="utf-8").close()
    return root


def _helper_flags74(root):
    real_lstat = os.lstat
    locked = os.path.join(root, "locked", ".restart-pending")

    def _lstat(path, *a, **k):
        # root's EACCES on an NFS root_squash home, which a root test run cannot produce for real
        if path == locked:
            raise PermissionError(13, "Permission denied", path)
        return real_lstat(path, *a, **k)
    _p9_patch(_helper, "HOME_ROOT", root)
    # The helper's own handle on os, never os.lstat itself (review 1013a: that was process-wide).
    os_saved = _helper.os
    _p9_patch(_helper, "os", _R20dOver(os_saved, lstat=_lstat))
    out, err = _io74.StringIO(), _io74.StringIO()
    try:
        with _ctx74.redirect_stdout(out), _ctx74.redirect_stderr(err):
            rc = _helper.do_restart_flags([], None)
    finally:
        _helper.os = os_saved
    check("helper restart-flags: a home it could not look in is named (`?<name>`) and the verb exits 0 "
          "— its exit 1 made the panel drop the whole host's answer — with the homes it read listed",
          rc == 0 and out.getvalue().split() == ["flagged", "?locked"], repr((rc, out.getvalue())))


def _remote_flags74(root):
    sh = _priv74.remote_command("restart-flags", [])
    sh = sh.replace("cd /home ", "cd %s " % root).replace("f=/home/", "f=%s/" % root)
    # `cd` refused for one home, as an EACCES home is to root on NFS root_squash; a root test run
    # cannot produce that with modes.
    stub = 'cd() { case "$*" in *locked*) return 1;; esac; builtin cd "$@"; }; '
    r = _sp74.run(["/bin/bash", "-c", stub + sh],  # nosec B603 - bash on this repo's own command
                  capture_output=True, text=True, timeout=20, check=False)
    gone = _sp74.run(["/bin/bash", "-c", sh.replace(root, root + "-missing")],  # nosec B603 - as above
                     capture_output=True, text=True, timeout=20, check=False)
    check("remote restart-flags: a home the shell cannot enter is named as unread, not dropped from "
          "the glob into a confident \"no flag\" with rc 0, and a flagged home is still listed",
          r.returncode == 0 and r.stdout.split() == ["%s/flagged/.restart-pending" % root, "?locked"],
          repr((r.returncode, r.stdout, r.stderr)))
    check("remote restart-flags: ...and a /home that cannot be listed is a failed read (non-zero), "
          "not an empty answer", gone.returncode != 0 and not gone.stdout.strip(),
          repr((gone.returncode, gone.stdout)))
    _p9_patch(_mon74, "run_privileged", lambda *a, **k: (r.stdout.replace(root, "/home"), "", 0))
    flags = _mon74._host_restart_flags(NS())
    check("monitoring: the remote form's answer parses to the flagged account plus the unread marker",
          flags == {"flagged", "?locked"}, repr(flags))
    return flags


def _monitor74(flags, sid):
    _p9_patch(_mon74, "_server_transition", lambda *a, **k: _mon74._IN_MAINTENANCE)
    _p9_patch(_mon74.notifications, "alerts_muted", lambda gs: False)
    got = {}
    for acct, before in (("locked", True), ("flagged", False), ("clear", True)):
        _mon74._cron_restart_pending[sid] = before
        gs = NS(id=sid, status="online", port=27074, short_name=acct)
        _mon74._monitor_server(None, gs, {"restart_flagged": flags}, {27074})
        got[acct] = _mon74._cron_restart_pending.get(sid)
    check("monitoring: an account whose home could not be looked in keeps the banner it had, while "
          "the same read still sets a flagged account's and clears a clear one's (one such home "
          "used to freeze every banner on the host)",
          got == {"locked": True, "flagged": True, "clear": False}, repr(got))
    probes = {sid: {"restart_flagged": flags}}
    _mon74._restart_flags_read_at.pop(sid, None)
    _mon74._stamp_flag_reads(probes, {sid})
    stamped = sid in _mon74._restart_flags_read_at
    _mon74._restart_flags_read_at.pop(sid, None)
    check("monitoring: ...and that read is stamped, so the host goes back to one read per 600 s",
          stamped, repr(stamped))


try:
    _arm74()
    _HOST74, _GS74, _ADMIN74, _CMD74 = _setup74()
    _A74 = _p9_client(_ADMIN74)
    _names74()
    _control74(_A74, _GS74, _CMD74)
    _ipv6_74(_A74, _HOST74)
    _privacy74()
    _cutoff74()
    _ROOT74 = _homes74()
    _helper_flags74(_ROOT74)
    _monitor74(_remote_flags74(_ROOT74), _GS74)
finally:
    _p9_restore_all()
    _cleanup74()

check("part74: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP74_START, repr(_P9_TRIPPED[_TRIP74_START:][:6]))
