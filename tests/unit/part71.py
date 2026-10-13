"""Part 71 of the unit suite: the seventh review's fixes (review 1012b, builder B).

Game files, the debug report, the privileged helper and routes:

* GMod Content card: a finished content job's outcome — the failed install, the unconfirmed
  removal, "Mounted: … restart the server to apply" — is shown on the card, in the viewer's
  language. The server kept it for 15 minutes; the card read job.msg only while the job ran, so
  every outcome ended in silence.

* Return to Castle Wolfenstein: a Ban refused because an `exceptaddr` range covers the player says
  so (it was "Done."), and a player typing the refusal's words in chat cannot fake a refusal.

* idTech3 Kick/Ban by name: a name gamedig shows with its `^a`-style colour codes stripped finds
  its console row (only when exactly one player matches).

* Debug report: a JSON true in trusted_proxy_users is not counted as an account that exists; a
  very large audit_ip_retention_days no longer loses the Database section; a long token around a
  DOTTED known name is redacted whole.

* Helper: `restart-flags` names a home it could not look in (`?<name>`) instead of reading it as
  "no flag" (it exits 0 and says so; #427 replaced the non-zero exit this part first asserted).

* Routes: four fixed messages server_detail shows are translated (and the i18n gates now follow a
  helper's answer through a call, and a job's progress text through a callback); the root-capable
  reading refusal names the Scheduled Tasks it withholds.

HOW IT RUNS. On part12's Flask app and stubs, as part68 does; nothing reaches a transport. The card
is rendered by the page's own loadGmodContent, in node.
"""
import contextlib as _ctx71
import importlib.util as _ilu71
import io as _io71
import json as _json71
import os
import shutil as _shutil71
import tempfile as _tf71
import time as _time71
from types import SimpleNamespace as NS

from unit.part01 import check, skip
from unit.part05 import _helper, _root
from unit.part12 import (_P9_TRIPPED, _P9Thread, _p9, _p9_arm, _p9_client, _p9_core, _p9_drain, _p9_json,
                         _p9_patch, _p9_restore_all, _p9_sd, _p9_sf, _p9_sh, _p9_threading, _p9_trip)
from unit.part47 import _cut47, _node47
from flask import session as _session71
from panel.core import i18n as _i18n71
from panel.db.models import AuditLog, GameServer, RemoteServer, User, db
from panel.ops.debug_report import config_section as _cs71, data as _data71, privacy as _pv71
from panel.ops.debug_report._base import Ctx as _Ctx71
from panel.ops.ssh_manager import game as _game71, gmod as _gmod71
from panel.security import auth as _auth71

_TRIP71_START = len(_P9_TRIPPED)
_mine71 = {"hosts": [], "servers": [], "users": []}
_TMP71 = os.path.realpath(_tf71.mkdtemp(prefix="lgsm-unit-p71-"))

_spec71 = _ilu71.spec_from_file_location("i18n_scan_p71", os.path.join(_root, "tools", "i18n_scan.py"))
_scan71 = _ilu71.module_from_spec(_spec71)
_spec71.loader.exec_module(_scan71)


def _arm71():
    _p9_arm(who="part71")
    _p9_patch(_p9_core, "run_command", _p9_trip("run_command"))
    _p9_patch(_p9_core, "shell_as_game_user", _p9_trip("shell_as_game_user"))
    _p9_patch(_p9_core, "run_privileged", _p9_trip("run_privileged"))


def _setup71():
    with _p9.app_context():
        r = RemoteServer(name="p71-host", host="192.0.2.171", port=22, username="admin",
                         auth_method="key", auth_credential="", is_online=True)
        db.session.add(r)
        db.session.commit()
        gm = GameServer(remote_id=r.id, name="p71-gmod", short_name="p71gmod", game_type="gmod",
                        port=27071, installed=True, status="offline")
        on = GameServer(remote_id=r.id, name="p71-online", short_name="p71on", game_type="csgo",
                        port=27072, installed=True, status="online")
        admin = User(username="p71_admin", password_hash=_auth71.hash_password("Str0ng!passw0rd-p71"),
                     display_name="p71 admin", is_superadmin=True, is_active=True)
        db.session.add_all([gm, on, admin])
        db.session.commit()
        _mine71["hosts"].append(r.id)
        _mine71["servers"] += [gm.id, on.id]
        _mine71["users"].append(admin.id)
        return r.id, gm.id, on.id, admin.id


def _cleanup71():
    with _p9.app_context():
        for i in _mine71["servers"]:
            AuditLog.query.filter_by(game_server_id=i).delete()
        AuditLog.query.filter(AuditLog.username.like("p71%")).delete(synchronize_session=False)
        db.session.commit()
        for model, key in ((GameServer, "servers"), (User, "users"), (RemoteServer, "hosts")):
            for i in _mine71[key]:
                row = db.session.get(model, i)
                if row is not None:
                    db.session.delete(row)
            db.session.commit()
    for sid in _mine71["servers"]:
        _p9_sf._gmod_content_apply_state.pop(sid, None)
    _shutil71.rmtree(_TMP71, ignore_errors=True)


def _lang71(lang):
    with _p9.app_context():
        db.session.get(User, _ADMIN71).language = lang
        db.session.commit()


def _as_lang71(lang, call):
    """`call()` with the admin's UI language set to `lang`, then English again."""
    _lang71(lang)
    try:
        return call()
    finally:
        _lang71("en")


def _in_lang71(lang, call):
    """`call()` inside a request whose viewer chose `lang` (the session's choice)."""
    with _p9.test_request_context("/"):
        _session71["lang"] = lang
        return call()


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 1. GMod Content card: a finished job's outcome reaches the card, in the viewer's language
# ════════════════════════════════════════════════════════════════════════════════════════════════
_GMC71 = {"cu": None, "installed": [], "removed": []}


def _gmc_stubs71():
    _p9_patch(_p9_sf, "threading", _p9_threading(_P9Thread))
    _p9_patch(_p9_sf, "gmod_current_mounts", lambda remote, user: [])
    _p9_patch(_p9_sf, "detect_content_user", lambda remote, games: _GMC71["cu"])
    _p9_patch(_p9_sf, "ensure_content_user", lambda remote: _GMC71["cu"])
    _p9_patch(_p9_sf, "path_disk_free", lambda remote, path: (50 * 2 ** 30, 100 * 2 ** 30))
    _p9_patch(_p9_sf, "install_gmod_content",
              lambda remote, cu_user, games: (True, list(_GMC71["installed"]), ""))
    _p9_patch(_p9_sf, "uninstall_gmod_content",
              lambda remote, cu_user, games: (True, list(_GMC71["removed"]), ""))
    _p9_patch(_p9_sf, "gmod_mount_setup", lambda remote, user, cu_user, games: (
        True, _i18n71.Sentence("Mounted: {games} — restart the server to apply",
                               games=", ".join(_gmod71.GMOD_CONTENT_GAMES[g][0] for g in games))))


def _gmc_job71(client, gid, body):
    """POST `body`, run the worker, then GET the card's status; -> its JSON."""
    _p9_sf._release_gmod_content_host(_HOST71)
    client.post("/api/server/%d/gmod-content" % gid, json=body)
    _p9_drain()
    return _p9_json(client.get("/api/server/%d/gmod-content" % gid))


def _body71(action, games):
    return {"action": action, "games": games}


def _gmod_outcomes71(client, gid):
    _gmc_stubs71()
    got = {}
    # No content storage: the error the docstring of _gmod_job_state names first.
    _GMC71["cu"] = None
    got["no storage es"] = _as_lang71("es", lambda: _gmc_job71(client, gid, _body71("mount", ["cstrike"])))
    got["no storage en"] = _p9_json(client.get("/api/server/%d/gmod-content" % gid))
    # A download that did not land: the mounted half and the missing half, in French.
    _GMC71["cu"] = {"user": "gmcontent", "present": {"tf": 1}}
    got["missing fr"] = _as_lang71("fr", lambda: _gmc_job71(client, gid, _body71("mount", ["tf", "cstrike"])))
    # An uninstall the host stopped answering about.
    _GMC71["removed"] = []
    got["unconfirmed es"] = _as_lang71("es", lambda: _gmc_job71(client, gid, _body71("uninstall", ["cstrike"])))
    # Success: "Mounted: … — restart the server to apply".
    _GMC71["cu"] = {"user": "gmcontent", "present": {"cstrike": 1}}
    got["done es"] = _as_lang71("es", lambda: _gmc_job71(client, gid, _body71("mount", ["cstrike"])))
    job = {k: (v.get("job") or {}) for k, v in got.items()}
    check("GMod content (es viewer): a content job that FAILED reaches the card's status poll with "
          "its outcome in the viewer's language — no storage, a download that did not land, a "
          "removal the host would not confirm",
          all((job["no storage es"].get("status") == "error",
               job["no storage es"].get("msg") == "No se pudo preparar el almacenamiento de contenido en el host.",
               job["missing fr"].get("status") == "error",
               job["missing fr"].get("msg", "").startswith(
                   "Non confirmé sur l'hôte, donc non monté : Counter-Strike: Source."),
               "Monté : Team Fortress 2" in job["missing fr"].get("msg", ""),
               job["unconfirmed es"].get("status") == "error",
               job["unconfirmed es"].get("msg", "").startswith(
                   "No se pudo confirmar la eliminación de cstrike"))), repr(job))
    check("GMod content (es viewer): ...and a job that succeeded says what it mounted and that a "
          "restart applies it",
          (job["done es"].get("status"), job["done es"].get("msg")) == (
              "done", "Montado: Counter-Strike: Source. Reinicia el servidor para aplicarlo"),
          repr(job["done es"]))
    st = _p9_sf._gmod_job_state(gid) or {}
    check("GMod content: ...while the stored state stays English, for the logs, and an English "
          "viewer reads it as it was (control)",
          (str(st.get("msg")), job["no storage en"].get("msg")) == (
              "Mounted: Counter-Strike: Source — restart the server to apply",
              "No content storage could be prepared on the host."),
          repr((st, job["no storage en"])))


# ── the card itself: the page's loadGmodContent, run in node on each answer ─────────────────────
def _card71(answer):
    """What loadGmodContent draws for one status answer; None without node.

    Its markup, and the outcome slot as the nodes _gmcOutcome put in it.
    """
    src = open(os.path.join(_root, "static", "js", "server_detail.js"), encoding="utf-8").read()
    prog = ("const settle = async () => { for (let i = 0; i < 6; i++) await new Promise(r => setImmediate(r)); };\n"
            "const slot = {id: 'gmc-outcome-slot', className: '', removed: false, attrs: {}, kids: [],\n"
            "  remove() { this.removed = true; }, setAttribute(k, v) { this.attrs[k] = v; },\n"
            "  appendChild(n) { this.kids.push(n); }};\n"
            "const el = {innerHTML: '', querySelectorAll: () => [],\n"
            "  querySelector: q => q === '#gmc-outcome-slot' && el.innerHTML.includes('gmc-outcome-slot')\n"
            "    ? slot : null};\n"
            "global.window = global; global.MOUNT = ''; global.serverId = 1; let timers = 0;\n"
            "global.setTimeout = () => { timers++; };\n"
            "global.document = {getElementById: id => id === 'gmod-content-body' ? el : null,\n"
            "  createElement: tag => ({tag, className: ''}), createTextNode: text => ({text})};\n"
            "const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')"
            ".replace(/\"/g,'&quot;');\n"
            "global._esc = esc; global.escapeHtml = esc; global.t = s => s;\n"
            "global.tfHtml = (s, v) => s.replace(/\\{(\\w+)\\}/g, (m, k) => v && k in v ? "
            "(typeof v[k] === 'object' ? v[k].html : esc(v[k])) : m);\n"
            "global.fetch = () => Promise.resolve({json: () => Promise.resolve(%s)});\n"
            % _json71.dumps(answer)
            + _cut47(src, "function loadGmodContent(") + "\n"
            # absent from a page that has no outcome line: the checks below fail by name, not crash
            + (_cut47(src, "function _gmcOutcome(") if "function _gmcOutcome(" in src else "") + "\n"
            "(async () => { loadGmodContent(); await settle();\n"
            "  console.log(JSON.stringify({html: el.innerHTML, timers, slot})); })();\n")
    return _node47(prog)


def _gmod_card71():
    games = [{"key": "cstrike", "label": "Counter-Strike: Source", "size": "13 GB", "present": False,
              "mounted": False, "downloadable": True}]
    base = {"games": games, "mounted": [], "mounts_readable": True, "disk_free": 50 * 2 ** 30,
            "disk_total": 100 * 2 ** 30}
    err_msg = "No se pudo preparar el almacenamiento de contenido en el host."
    done_msg = "Montado: Counter-Strike: Source. Reinicia el servidor <b>para</b> aplicarlo"
    cards = {tag: _card71(dict(base, job=job)) for tag, job in (
        ("error", {"status": "error", "msg": err_msg, "ts": 1}),
        ("done", {"status": "done", "msg": done_msg, "ts": 1}),
        ("running", {"status": "running", "msg": "", "ts": 1}),
        ("none", None))}
    if any(c is None for c in cards.values()):
        skip("GMod content card: the finished job's outcome is drawn", "node is not installed here")
        return
    _card_checks71(cards, err_msg)


def _card_checks71(cards, err_msg):
    html = {k: v.get("html") or repr(v) for k, v in cards.items()}
    slot = {k: v.get("slot") or {} for k, v in cards.items()}
    check("GMod content card: a job that ENDED IN ERROR shows its message, in red, above Apply — "
          "the card read job.msg only while the job ran, so a failed install ended in silence",
          all((slot["error"].get("id") == "gmc-outcome", "text-danger" in slot["error"].get("className", ""),
               {"text": " " + err_msg} in slot["error"].get("kids", []), not slot["error"].get("removed"),
               0 <= html["error"].find("gmc-outcome-slot") < html["error"].find('id="gmc-apply"'))),
          repr((slot["error"], html["error"][-400:])))
    check("GMod content card: ...a job that finished shows its outcome in green, as a TEXT node (the "
          "message can quote host output; it is never markup)",
          all(("text-success" in slot["done"].get("className", ""),
               {"text": " Montado: Counter-Strike: Source. Reinicia el servidor <b>para</b> aplicarlo"}
               in slot["done"].get("kids", []))), repr(slot["done"]))
    check("GMod content card: ...a running job still shows the spinner and polls again, and no job "
          "shows no outcome line (controls)",
          all(("spinner-border" in html["running"], "gmc-outcome-slot" not in html["running"],
               cards["running"].get("timers") == 1, slot["none"].get("removed") is True,
               'id="gmc-apply"' in html["none"])), repr((html["running"][-300:], slot["none"])))


def _gmod_progress71():
    said = []
    _p9_patch(_gmod71, "content_present", lambda server, user, g: False)
    _p9_patch(_gmod71._core, "shell_as_game_user", lambda *a, **k: ("", "", 0))
    _gmod71._install_content_game(None, "gmcontent", "cstrike", said.append)
    es = _in_lang71("es", lambda: [_i18n71.tr(s) for s in said])
    check("GMod install (es viewer): the content download's progress text is a whole Sentence, "
          "so the install card's step name reads in Spanish for the whole download (it was "
          "spliced English that no key matched)",
          said and isinstance(said[0], _i18n71.Sentence)
          and es == ["Instalando el contenido de Counter-Strike: Source con LinuxGSM"], repr((said, es)))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 2. Return to Castle Wolfenstein: a ban an address exception refused; chat cannot fake a refusal
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _rtcw71():
    reply = {"text": ""}
    _p9_patch(_p9_core, "send_console_command", lambda *a, **k: ("PANE_MARK 1200 17 80\n", "", 0))
    _p9_patch(_game71, "capture_console", lambda *a, **k: (reply["text"], "", 0))
    _p9_patch(_game71, "time", NS(sleep=lambda s: None, time=_time71.time, gmtime=_time71.gmtime,
                                  strftime=_time71.strftime, monotonic=_time71.monotonic))
    got = {}
    for tag, text in (
            ("exception", "banaddr 2; kicknum 2\nError: Exception 203.0.113.0/24 supersedes ban "
                          "203.0.113.50/32\nGriefer was kicked\n"),
            ("broader ban", "Error: Ban 203.0.113.0/24 supersedes ban 203.0.113.50/32\n"),
            ("chat", "say: Prankster: Error: Can ban players connected via the internet only.\n"
                     "say: Prankster: Error: Exception 1.2.3.4/8 supersedes ban\nAdded ban: 203.0.113.5/32\n"),
            ("bot", "Error: Can ban players connected via the internet only.\n")):
        reply["text"] = text
        got[tag] = _game71.moderate(None, "p71rtcw", "rtcw", "ban", num="2")
    check("moderation (iortcw): a Ban refused because an `exceptaddr` range covers the player "
          "answers that the player was kicked but not banned, naming the exception (it was "
          "\"Done.\", a success row, and the griefer rejoined)",
          got["exception"][0] is False and "exceptaddr" in got["exception"][1]
          and "kicked but not banned" in got["exception"][1], repr(got["exception"]))
    check("moderation (iortcw): ...a broader BAN covering the address is still \"Done.\" (the player "
          "is banned), and the bot refusal still says so (controls)",
          got["broader ban"] == (True, "Done.") and got["bot"][0] is False
          and "bans only players connected over the internet" in got["bot"][1], repr(got))
    check("moderation (iortcw): ...and a player typing a refusal's words in chat cannot turn a ban "
          "that landed into a reported refusal: only a console line STARTING with the engine's "
          "`Error: ` counts", got["chat"] == (True, "Done."), repr(got["chat"]))
    msg = _in_lang71("fr", lambda: _i18n71.tr(got["exception"][1]))
    check("moderation (fr viewer): ...and the exception's answer is in the viewer's language",
          msg.startswith("Le joueur a été expulsé mais pas banni : une exception d'adresse"), msg)


def _wide_names71():
    rows = {"one": [{"num": 0, "name": "^aBob^7"}, {"num": 1, "name": "Alice"}],
            "two": [{"num": 0, "name": "^aBob"}, {"num": 1, "name": "^bBob"}],
            "exact": [{"num": 0, "name": "^1Bob"}, {"num": 3, "name": "^aBob"}]}
    got = {}
    for tag, listed in rows.items():
        _p9_patch(_game71, "console_player_list", lambda *a, _l=listed, **k: list(_l))
        hit = _game71._resolve_from_console(None, "p71q3", "q3", "Bob", None)
        got[tag] = None if hit is None else hit["num"]
    check("moderation (idTech3): a name gamedig shows with a `^a`-style colour code stripped (as id's "
          "Quake III and JK2MV's 1.02 colour mode read one) finds its console row — the console kept "
          "\"^aBob\" and the Kick found no one",
          got["one"] == 0, repr(got))
    # "exact" was a control that a `^1` match wins; the 1012c review showed it is the same ambiguity
    # ("^1Bob" and "^aBob" are one "Bob" on screen), so it resolves to no one now (part74).
    check("moderation (idTech3): ...but not when two players differ only in such codes (they are one "
          "row on screen; the first could be the wrong player), a `^1` code included",
          got["two"] is None and got["exact"] is None, repr(got))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 3. Debug report: proxy users, a huge IP retention, a long token around a dotted name
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _report71():
    got = (_cs71._proxy_users_existing([True, "root"]), _cs71._proxy_users_existing(True),
           _cs71._proxy_users_existing([False, 4242]))
    check("debug report: a JSON true/false in trusted_proxy_users is not counted as an account that "
          "exists (auth trusts no uid for it, so the report said \"2 of 2\" for one), and a uid still "
          "is (control)", got == ((1, 2), (0, 1), (1, 2)), repr(got))


def _census71():
    q = {}
    for days in (90, 10 ** 6, 10 ** 12, 10 ** 300):
        try:
            q[days] = sorted(_data71._census_queries(days))
        except Exception as exc:  # noqa: BLE001 - the failure is what this records
            q[days] = type(exc).__name__
    texts = {d: _data71._audit_ips_text((None, d), None) for d in (90, 10 ** 6, 10 ** 12, -5)}
    check("debug report: a very large audit_ip_retention_days builds the Database section's queries "
          "(1e12 days raised OSError outside any guard, and the whole section read \"could not be read\")",
          all((q[10 ** 12] == q[10 ** 300] == ["audit_log", "host_sample", "metric_sample"],
               "audit_ips" in q[90])), repr(q))
    check("debug report: ...and says IP reduction is off for such a value (the panel's own ageing "
          "raises on it), not \"IPs reduced after N d\"; a normal value still says it (control)",
          all((texts[10 ** 12].startswith("IP reduction off ("), texts[10 ** 6].startswith("IP reduction off ("),
               texts[90] == "IPs reduced after 90 d", texts[-5] == "IP reduction off")), repr(texts))


def _dotted71():
    st = _pv71._State()
    st.add("alice.smith", "account", 1)
    ctx = _Ctx71()
    ctx._memo["privacy"] = (True, st)
    left, right = "Q2hhcmxpZUJyb3du" + "eHl6Zm9v", "OTk4NzY1NDMyMWFi" + "Y2RlZmdo"
    out = _pv71.scrub(ctx, "x %s-alice.smith-%s y\nplain alice.smith here\nshort a-alice.smith-b"
                      % (left, right))
    check("debug report privacy: a 28+-character token around a DOTTED known name is redacted whole "
          "— the '.' ended the token, so both halves printed beside the name's token",
          left not in out and right not in out and "x [redacted] y" in out, out)
    check("debug report privacy: ...the name alone is still its token, and a short run around it is "
          "not redacted (controls)", "plain [account-1] here" in out and "short a-[account-1]-b" in out,
          out)


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 4. Helper: restart-flags says when it could not look
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _restart_flags71():
    root = os.path.join(_TMP71, "home")
    for acct, flag in (("flagged", True), ("clear", False), ("locked", False)):
        os.makedirs(os.path.join(root, acct))
        if flag:
            open(os.path.join(root, acct, ".restart-pending"), "w", encoding="utf-8").close()
    real_lstat = os.lstat
    locked = os.path.join(root, "locked", ".restart-pending")

    def _lstat(path, *a, **k):
        # root's EACCES on an NFS root_squash home, which a root test run cannot produce for real
        if path == locked:
            raise PermissionError(13, "Permission denied", path)
        return real_lstat(path, *a, **k)
    _p9_patch(_helper, "HOME_ROOT", root)
    _p9_patch(_helper.os, "lstat", _lstat)
    out, err = _io71.StringIO(), _io71.StringIO()
    with _ctx71.redirect_stdout(out), _ctx71.redirect_stderr(err):
        rc = _helper.do_restart_flags([], None)
    _helper.os.lstat = real_lstat
    # Since review 1012c the unread home is named on stdout (`?locked`) with exit 0, so the panel
    # keeps only that account's banner (part74); it is still never a confident "no flag".
    check("helper restart-flags: a home it could not look in is reported as unread, not a confident "
          "\"no flag\" — and the homes it could read are still listed",
          rc == 0 and out.getvalue().split() == ["flagged", "?locked"] and "locked" in err.getvalue(),
          repr((rc, out.getvalue(), err.getvalue())))


# ════════════════════════════════════════════════════════════════════════════════════════════════
# 5. Routes: four fixed messages, the gates that missed them, and the Scheduled Tasks refusal
# ════════════════════════════════════════════════════════════════════════════════════════════════
def _route_messages71(client, oid):
    es = _in_lang71("es", lambda: (_p9_sd._console_send_failure(3, ""),
                                   _p9_sd._console_send_failure(1, "")))
    check("server page (es viewer): the console's \"not running\" and \"gave no reason\" answers are "
          "in Spanish (they were bare English literals no gate saw)",
          es == ("Ese servidor no está en marcha, así que no hay una sesión de consola a la que enviar.",
                 "El panel no pudo ejecutar eso en el host, y no dio ningún motivo."), repr(es))
    _p9_patch(_p9_sd, "_live_run_state", lambda gs, remote: True)
    resp = _as_lang71("es", lambda: client.post("/api/server/%d/action" % oid, json={"action": "start"}))
    d = _p9_json(resp)
    check("server page (es viewer): Start on a server that is already running is refused in Spanish, "
          "as a whole sentence (it was the bots' lower-case English fragment)",
          d.get("success") is False
          and d.get("message") == "Ese servidor ya está en marcha. Usa 'restart' si quieres reiniciarlo.",
          repr(d))
    with _p9.app_context():
        gs = db.session.get(GameServer, oid)
        gs.status = "offline"
        db.session.commit()
    _p9_patch(_p9_sd, "_live_run_state", lambda gs, remote: False)
    d = _p9_json(_as_lang71("fr", lambda: client.post("/api/server/%d/action" % oid,
                                                      json={"action": "stop"})))
    check("server page (fr viewer): ...and Stop on one already stopped, in French",
          d.get("success") is False and d.get("message") == "Ce serveur est déjà arrêté.", repr(d))

    why = _p9_sh._privileged_write_msg("ubuntu", "it is in the sudo group", reading=True)
    tr = {lg: _in_lang71(lg, lambda: _i18n71.tr(why)) for lg in ("es", "fr")}
    check("Files & Config: the root-capable account's reading refusal — the one message on an empty "
          "Scheduled Tasks card — says the scheduled tasks are not listed, as its two siblings do, "
          "in es and fr too",
          "list its scheduled tasks" in why and "tareas programadas" in tr["es"]
          and "tâches planifiées" in tr["fr"], repr((why, tr)))


_GATE_ROUTES71 = (
    "def _failure(rc):\n"
    "    if rc == 3:\n"
    "        return 'Not running, so nothing was sent.'\n"
    "    return 'It gave no reason at all.'\n"
    "def _refusal(gs):\n"
    "    return 'already running. Use restart.'\n"
    "def _act(gs):\n"
    "    refusal = _refusal(gs)\n"
    "    if refusal:\n"
    "        return False, refusal\n"
    "    return True, 'ok'\n"
    "def _said(msg):\n"
    "    return i18n.tr(msg)\n"
    "def a(rc):\n"
    "    flash(_failure(rc), 'warning')\n"                          # a helper's literal, flashed
    "def b(gs):\n"
    "    ok, msg = _act(gs)\n"
    "    return jsonify({'message': _said(msg)})\n"                  # through a pass-through helper
    "def c(remote):\n"
    "    install(remote, on_progress=lambda m: _p(8, m))\n"           # a job writer in a callback
    "def d(remote):\n"
    "    other(remote, on_step=lambda m: _p(9, m))\n")               # a callback nothing feeds
_GATE_OPS71 = ("def install(remote, on_progress=None):\n"
               "    on_progress('Installing %s content' % remote)\n"
               "    on_progress('Fetching the content')\n")


def _gate_tree71():
    """A throwaway tree holding the two fixture modules above; its root."""
    td = os.path.realpath(_tf71.mkdtemp(prefix="lgsm-unit-p71-scan-", dir=_TMP71))
    for d in (("panel", "routes"), ("panel", "ops"), ("translations", "es")):
        os.makedirs(os.path.join(td, *d))
    for rel, text in (("app.py", ""), ("translations/es/x.json", "{}"),
                      ("panel/routes/r.py", _GATE_ROUTES71), ("panel/ops/s.py", _GATE_OPS71)):
        with open(os.path.join(td, *rel.split("/")), "w", encoding="utf-8") as fh:
            fh.write(text)
    return td


def _gates71():
    td = _gate_tree71()
    try:
        gaps = sorted(k for k, _w in _scan71.route_answer_gaps(
            "es", root=td, translation_dir=os.path.join(td, "translations")))
        steps = sorted(_scan71.step_name_keys(root=td))
        built = _scan71.step_names_built(root=td)
    finally:
        _shutil71.rmtree(td, ignore_errors=True)
    check("i18n gate: a route's answer is followed into a helper CALLED in the sink (flash(_failure(rc)))"
          " and through a helper handed the service's answer (_said(msg)) — server_detail's four fixed "
          "messages had no es/fr entry and every gate passed",
          gaps == sorted(["Not running, so nothing was sent.", "It gave no reason at all.",
                          "already running. Use restart."]), repr(gaps))
    check("i18n gate: a job's progress text handed through a callback (`on_progress=lambda m: _p(8, m)`)"
          " is read at the callee's calls: a literal is a key, a % one is reported built, and a "
          "callback no call feeds is reported (it was invisible: the walk never entered a lambda)",
          (steps, sorted(built)) == (["Fetching the content"],
                                     [("panel/ops/s.py", 2), ("panel/routes/r.py", 22)]),
          repr((steps, built)))


def _gates_panel71():
    shown = _scan71.route_answer_keys()
    catalogs = {lg: _scan71.load_catalog(lg) for lg in ("es", "fr")}
    missing = [(lg, k) for lg in catalogs for k in shown if k not in catalogs[lg]]
    built = _scan71.step_names_built()
    check("i18n gate: ...and over the panel, every answer the wider follow finds is in both catalogs, "
          "with no progress text built in plain English",
          all((len(shown) >= 470, not missing, built == [])), repr((len(shown), missing[:6], built[:4])))


try:
    _arm71()
    _HOST71, _GM71, _ON71, _ADMIN71 = _setup71()
    _A71 = _p9_client(_ADMIN71)
    _gmod_outcomes71(_A71, _GM71)
    _gmod_card71()
    _gmod_progress71()
    _rtcw71()
    _wide_names71()
    _report71()
    _census71()
    _dotted71()
    _restart_flags71()
    _route_messages71(_A71, _ON71)
    _gates71()
    _gates_panel71()
finally:
    _p9_restore_all()
    _cleanup71()

check("part71: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP71_START, repr(_P9_TRIPPED[_TRIP71_START:][:6]))
