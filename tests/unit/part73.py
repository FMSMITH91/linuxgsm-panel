"""Part 73 of the unit suite: review 1012c's core, backup, ssh-core and reboot fixes (builder A).

Held here, each against the code path the finding named:

* an IPv6 host's connect address is bracketed on the host's Manage page and in the chat bot's
  /connect reply, and an IPv6 panel bind wherever it is shown before a `:port`;
* a console line holding a control character is refused up front by the custom-command route, and
  moderation neither types a player name holding one nor reports it as "Console not reachable";
* a remote's fail2ban whitelist that was not written or not reloaded is a failure, and is logged;
* a LinuxGSM command in flight holds a reboot plan row for a day, not for ever, and a rollback whose
  host stays silent for STALE_PLAN has its plan dropped;
* the update card's merge-base and the test branch's rev-parse reads: a failed read is not an answer.

HOW IT RUNS. Pure functions and part12's Flask app and database, with every outside call stood in
for (part20's _patch / _patched, undone at the end of each block), and node on this part's own
fixtures. Nothing touches the network, sudo, a real host or the checkout's data/.
"""
import json as _json73
import os as _os73
import types as _types73


import app as _app73
from unit.part01 import check, skip
from unit.part12 import P9_ADMIN, P9_GS, _P9_TRIPPED, _p9, _p9_arm, _p9_client
from unit.part20 import _patch, _patched
from unit.part47 import _node47
from unit.part51 import _bootstrap51
from panel.core import config as _cfg73
from panel.db import models as _models73
from panel.ops import system_ops as _so73
from panel.ops.ssh_manager import _core as _smc73
from panel.ops.ssh_manager import firewall as _smf73
from panel.ops.ssh_manager import game as _smg73
from panel.ops.ssh_manager import hosts as _smh73
from panel.routes import os_updates as _osu73
from panel.routes import remote_security as _rs73
from panel.routes import server_detail as _sd73
from panel.services import host_reboot as _hr73
from panel.services import reboot_words as _rw73
from panel.services.bots import commands as _bot73

NS = _types73.SimpleNamespace
_ROOT73 = _os73.path.dirname(_os73.path.dirname(_os73.path.dirname(_os73.path.abspath(__file__))))


def _read73(*parts):
    with open(_os73.path.join(_ROOT73, *parts), encoding="utf-8") as fh:
        return fh.read()


def _cat73(lang):
    out = {}
    folder = _os73.path.join(_ROOT73, "translations", lang)
    for name in sorted(_os73.listdir(folder)):
        if name.endswith(".json"):
            out.update(_json73.loads(_read73("translations", lang, name)))
    return out


_CAT73 = {lg: _cat73(lg) for lg in ("es", "fr")}


def _as73(lang):
    """Set P9_ADMIN's saved language (the account's choice wins over the session's)."""
    with _p9.app_context():
        _models73.db.session.get(_models73.User, P9_ADMIN).language = lang
        _models73.db.session.commit()


# The account's language as this part found it, put back after each block that switches it, as
# part70 and part72 do (review 1012d: reset to "en", a later part would read this part's choice).
with _p9.app_context():
    _LANG73_WAS = _models73.db.session.get(_models73.User, P9_ADMIN).language


# ── A01: an IPv6 host's connect address, wherever it is printed ──────────────────────────────────
_V6_73 = "2001:db8::5"
_RM73 = _read73("templates", "remote_manage.html")
_cell73 = _RM73[_RM73.index("{% set addr = remote.connect_host %}"):]
_cell73 = _cell73[:_cell73.index("</td>")]
_gs73 = _models73.GameServer(name="p73", short_name="csgoserver", game_type="csgo", port=27015)
with _p9.test_request_context("/"):
    _html73 = _p9.jinja_env.from_string(_cell73).render(
        remote=NS(connect_host=_V6_73), gs=_gs73, t=lambda s, **k: s)
    _html4_73 = _p9.jinja_env.from_string(_cell73).render(
        remote=NS(connect_host="203.0.113.5"), gs=_gs73, t=lambda s, **k: s)
check("host page: an IPv6 host's game address is bracketed in the copy value, the shown text and the "
      "Join link's phone address (all three printed 2001:db8::5:27015, beside a bracketed Join link); "
      "an IPv4 one is as it was",
      _html73.count("[%s]:27015" % _V6_73) == 4 and "%s:27015" % _V6_73 not in _html73.replace(
          "[%s]:27015" % _V6_73, "")
      and _html4_73.count("203.0.113.5:27015") == 4, repr((_html73, _html4_73)))


def _connect73(remote):
    """_connect_text for one server on `remote`, its lookup stood in."""
    class _G:
        connect_address = _models73.GameServer.connect_address
        connect_uri = _models73.GameServer.connect_uri
    g = _G()
    g.name, g.port, g.game_type, g.remote = "p73", 27015, "csgo", remote
    with _patched():
        _patch(_bot73, "_find_server", lambda arg: (g, None))
        return _bot73._connect_text(_p9, "p73")


_bot6_73 = _connect73(NS(public_ip="", host=_V6_73, is_local=False))
_bot4_73 = _connect73(NS(public_ip="203.0.113.5", host="h", is_local=False))
check("chat bot: /connect prints an IPv6 address bracketed, above its steam:// link (it printed "
      "2001:db8::5:27015); an IPv4 one is as it was",
      _bot6_73 == "p73\n[%s]:27015\nsteam://connect/[%s]:27015" % (_V6_73, _V6_73)
      and _bot4_73 == "p73\n203.0.113.5:27015\nsteam://connect/203.0.113.5:27015", repr((_bot6_73, _bot4_73)))

_SC73 = _read73("templates", "setup_complete.html")
# The `<code>` that prints the running bind before its port, found by what it prints, not by how.
_rb73 = next((ln.strip() for ln in _SC73.splitlines() if "running_bind" in ln and "panel_port" in ln), "")
_rb73 = _rb73[_rb73.find("<code>"):_rb73.find("</code>") + len("</code>")]
_ANY4_73 = "0.0.0.0"  # nosec B104 - a bind value rendered and compared, never bound
_rbv73 = [_p9.jinja_env.from_string(_rb73).render(running_bind=b, panel_port=5000) for b in ("::", _ANY4_73)]
_rh73 = _read73("static", "js", "remote_manage_host.js")
_br73 = _rh73[_rh73.index("function _r18aBracket"):_rh73.index("function changePanelBinding")]
_cpb73 = _rh73[_rh73.index("function changePanelBinding"):_rh73.index("function _changePanelBinding")]
_js73 = _rh73[_rh73.index("var shownBind"):]
_js73 = _js73[:_js73.index("setTimeout")]
# The toast's own line and the confirm dialog's text, not only a variable: those are what the
# operator reads. The dialog is driven through changePanelBinding with a custom IPv6 bind.
_jsv73 = _node47(
    "let out = [];\nconst tfHtml = (s, o) => o.addr;\n" + _br73
    + "for (const d of [{new_bind: '::', new_port: 5000}, {new_bind: '0.0.0.0', new_port: 5000}]) {\n"
    + "const m = {};\n" + _js73 + "out.push(m.innerHTML); }\n"
    + "const _els = {'panel-port-input': {value: '5000'}, 'panel-bind-select': {value: '__custom__'},\n"
    + "              'panel-bind-custom': {value: ''}};\n"
    + "const document = {getElementById: (id) => _els[id]};\n"
    + "const tf = (s, o) => o.bind;\nconst confirmDialog = (o) => out.push(o.bodyText);\n" + _cpb73
    + "for (const b of ['2001:db8::5', '203.0.113.5']) { _els['panel-bind-custom'].value = b; "
    + "changePanelBinding(); }\nconsole.log(JSON.stringify(out));")
check("panel bind: an IPv6 bind is bracketed before its port on the setup page, in the binding reply, "
      "in the page's confirm dialog and in its restart toast (`:::5000` names no address); an IPv4 bind is as it was",
      _rbv73 == ["<code>[::]:5000</code>", "<code>0.0.0.0:5000</code>"]
      and _rs73._r18a_bracketed("::") == "[::]" and _rs73._r18a_bracketed(_ANY4_73) == _ANY4_73
      and _jsv73 in (None, ['<span class="text-success">[::]:5000</span>',
                            '<span class="text-success">0.0.0.0:5000</span>',
                            '[2001:db8::5]:5000', '203.0.113.5:5000']), repr((_rbv73, _jsv73)))
if _jsv73 is None:
    skip("panel bind: the restart toast's bracketing", "no node")

# part12's transport tripwire is armed inside each block below that drives a route (with part20's
# _patch, so the block's end undoes it); the part ends by checking nothing reached a real host.
_TRIP73_START = len(_P9_TRIPPED)
# The route's own reply, not only the helper: driven through Change binding to "::".
_cfg_before73 = _cfg73.load_config()
# The audit rows counted from here (review 1012d): the newest row in the database was read, and
# part53 had already written one with the same detail, so a request that audited nothing passed.
with _p9.app_context():
    _cpa_from73 = _models73.db.session.query(_models73.db.func.max(_models73.AuditLog.id)).scalar() or 0
try:
    _as73("es")
    with _patched():
        _p9_arm(patch=_patch, who="part73")
        _patch(_rs73, "remote_ufw_open_port", lambda *a, **k: (True, "ok"))
        _patch(_rs73, "remote_ufw_close_port", lambda *a, **k: (True, "ok"))
        _patch(_so73, "ensure_panel_fail2ban", lambda *a, **k: (True, "updated"))
        _patch(_so73, "restart_panel", lambda *a, **k: (True, "scheduled"))
        _patch(_so73, "port_in_use", lambda port: False)
        _patch(_so73, "panel_fail2ban_status", lambda: {"installed": True})
        _cfg73.save_config(dict(_cfg_before73, port=5000, bind_host=_ANY4_73))
        _cp73 = _p9_client(P9_ADMIN).post("/api/panel/change-port", json={"port": 5000, "bind_host": "::"})
finally:
    _as73(_LANG73_WAS)
    _cfg73.save_config(_cfg_before73)
_cpm73 = (_cp73.get_json() or {}).get("message") or ""
with _p9.app_context():
    _cpa73 = (_models73.AuditLog.query.filter_by(action="panel_change_binding")
              .filter(_models73.AuditLog.id > _cpa_from73).all())
    _cpd73 = _cpa73[0].detail if len(_cpa73) == 1 else "%d rows" % len(_cpa73)
check("panel bind: ...and Change binding's reply names an IPv6 bind bracketed, in the viewer's language, "
      "as its audit row does",
      _cp73.status_code == 200 and "[::]:5000" in _cpm73 and ":::5000" not in _cpm73
      and _cpm73 != "Panel binding to [::]:5000. Restarting…"
      and _cpd73.startswith("0.0.0.0:5000 -> [::]:5000;"), repr((_cp73.status_code, _cpm73, _cpd73)))

_rv6_73 = _models73.RemoteServer(name="p73", host=_V6_73, username="ubuntu", port=2222)
_rv4_73 = _models73.RemoteServer(name="p73", host="203.0.113.5", username="ubuntu", port=22)
_tpl_hp73 = [n for n in sorted(_os73.listdir(_os73.path.join(_ROOT73, "templates"))) if n.endswith(".html")
             and "remote.host }}:{{" in _read73("templates", n)]
check("host login: a remote's SSH login is shown with an IPv6 host bracketed (ubuntu@2001:db8::5:2222 "
      "named no address), an IPv4 one as it was, and no template prints `remote.host:port` itself",
      _rv6_73.login_address == "ubuntu@[%s]:2222" % _V6_73
      and _rv4_73.login_address == "ubuntu@203.0.113.5:22" and _tpl_hp73 == [],
      repr((_rv6_73.login_address, _rv4_73.login_address, _tpl_hp73)))


# ── A03: a console line holding a control character, from the custom-command route ───────────────
_cc_sent73 = []
with _p9.app_context():
    _cc73 = _models73.CustomCommand(name="p73 say", command_template="say {}", argument_pattern=".+",
                                    scope_type="all", enabled=True)
    _models73.db.session.add(_cc73)
    _models73.db.session.commit()
    _CC73 = _cc73.id
try:
    _as73("es")
    with _patched():
        _p9_arm(patch=_patch, who="part73")
        _patch(_sd73, "send_console_command", lambda *a, **k: _cc_sent73.append(a) or ("", "", 0))
        _c73 = _p9_client(P9_ADMIN)
        _ccr73 = _c73.post("/api/server/%d/custom-command/%d" % (P9_GS, _CC73), json={"value": "\x03"})
        _ccok73 = _c73.post("/api/server/%d/custom-command/%d" % (P9_GS, _CC73), json={"value": "hola"})
finally:
    _as73(_LANG73_WAS)
    # Removed as part53 and part74 remove theirs, so no later part inherits a command for every server.
    with _p9.app_context():
        _models73.db.session.delete(_models73.db.session.get(_models73.CustomCommand, _CC73))
        _models73.db.session.commit()
_CTRL_ES73 = _CAT73["es"].get("A console command can't contain control characters or line breaks.")
check("custom command: a value holding a control character, through a permissive stored pattern, is "
      "refused up front (400) in the viewer's language, and nothing is sent (it was a 502 \"could not run "
      "that on the host\" with the reason in English); an ordinary value still runs",
      _ccr73.status_code == 400 and (_ccr73.get_json() or {}).get("message") == _CTRL_ES73
      and bool(_CTRL_ES73) and _ccok73.status_code == 200 and len(_cc_sent73) == 1
      and _cc_sent73[0][2] == "say hola", repr((_ccr73.status_code, _ccr73.get_json(), _cc_sent73)))


# ── A03: moderation and a control character ──────────────────────────────────────────────────────
def _mod73(game_type, action, **kw):
    sent = []
    with _patched():
        _patch(_smc73, "shell_as_game_user", lambda s, u, inner, **k: sent.append(inner) or ("", "", 0))
        _patch(_smg73, "_resolve_from_console", lambda *a, **k: None)
        res = _smg73.moderate(None, "p73game", game_type, action, selfname="p73srv", **kw)
    return res, len(sent)


_kick73 = _mod73("csgo", "kick", target="\x07Bob")
_mckick73 = _mod73("mc", "kick", target="Bo\x1bb")
_say73 = _mod73("csgo", "say", message="\x1bhello\x07 all")
_plain73 = _mod73("csgo", "kick", target="Bob")
check("moderation: a player name holding a control character is refused in words of its own, and "
      "nothing is typed (the send's refusal read \"Console not reachable — is the server running?\"); "
      "an announcement drops the control characters and is sent; an ordinary kick still sends",
      _kick73 == ((False, _smg73.R18A_NAME_CONTROL), 0) and _mckick73 == ((False, _smg73.R18A_NAME_CONTROL), 0)
      and _say73 == ((True, "Done."), 1) and _plain73 == ((True, "Done."), 1),
      repr((_kick73, _mckick73, _say73, _plain73)))
check("moderation: ...and the refusal is in the es and fr catalogs",
      all(_CAT73[lg].get(_smg73.R18A_NAME_CONTROL) for lg in ("es", "fr")))
_mod_sent73 = []
try:
    _as73("fr")
    with _patched():
        _p9_arm(patch=_patch, who="part73")
        _patch(_smc73, "shell_as_game_user", lambda s, u, inner, **k: _mod_sent73.append(inner) or ("", "", 0))
        _modr73 = _p9_client(P9_ADMIN).post("/api/server/%d/moderate" % P9_GS,
                                            json={"action": "kick", "target": "\x07Bob"})
finally:
    _as73(_LANG73_WAS)
check("moderation: ...through the Players panel's route, the refusal reaches a fr viewer in French",
      (_modr73.get_json() or {}).get("message") == _CAT73["fr"].get(_smg73.R18A_NAME_CONTROL)
      and (_modr73.get_json() or {}).get("success") is False and _mod_sent73 == [],
      repr((_modr73.status_code, _modr73.get_json(), _mod_sent73)))


# ── A03: a remote's fail2ban whitelist that did not take ─────────────────────────────────────────
def _ignore73(write_rc, reload_rc):
    with _patched():
        _patch(_smc73, "run_privileged", lambda *a, **k: ("`- Jail list:\tsshd", "", 0))
        _patch(_smc73, "write_root_file", lambda *a, **k: ("", "timed out" if write_rc else "", write_rc))
        _patch(_smc73, "_f2b_reload", lambda *a, **k: ("", "", reload_rc))
        return _smh73.remote_set_fail2ban_ignoreip(NS(name="p73"), ["203.0.113.5"])


_ig_w73, _ig_r73, _ig_ok73 = _ignore73(-1, 0), _ignore73(0, 1), _ignore73(0, 0)
check("fail2ban whitelist: a remote whose drop-in write timed out, or whose fail2ban did not reload, "
      "answers False with why (both were statements, and it answered \"ignoreip applied\")",
      _ig_w73 == (False, "the whitelist drop-in could not be written")
      and _ig_r73 == (False, "fail2ban did not reload") and _ig_ok73 == (True, "ignoreip applied on p73")
      and all(_CAT73[lg].get(_ig_w73[1]) for lg in ("es", "fr")), repr((_ig_w73, _ig_r73, _ig_ok73)))

_warned73 = []
for _ans73 in ((False, "fail2ban did not reload"), (False, _smh73.F2B_NOT_INSTALLED), (True, "ok")):
    with _patched():
        _patch(_app73, "remote_set_fail2ban_ignoreip", lambda *a, _r=_ans73, **k: _r)
        _patch(_app73, "_log", NS(warning=lambda msg, *a: _warned73.append((_ans73[1], msg % a)),
                                  debug=lambda *a, **k: None))
        _patch(_app73, "load_config", lambda: {"security_whitelist": ["203.0.113.5"]})
        _app73._apply_whitelist_to_remotes(_p9)
check("fail2ban whitelist: ...and a remote it did not reach is named in the log; no fail2ban on a host "
      "is not a failure, and one that took logs nothing",
      len(_warned73) >= 1 and {w[0] for w in _warned73} == {"fail2ban did not reload"}
      and all("fail2ban did not reload" in w[1] for w in _warned73), repr(_warned73))


# ── A05: a LinuxGSM command in flight, and a rollback's silent host ──────────────────────────────
def _held73(detail_at, rollback=False):
    """_act over one panel-owned row whose start waits; `detail_at` is [(now, detail)]."""
    gs = NS(id=-73, lgsm_name="p73srv", short_name="p73", name="p73")
    d = {"restore": "pending", "owner": "panel", "stop": "stopped"}
    finished = []
    with _patched():
        _patch(_hr73, "_scope_ready", lambda remote, row, now: True)
        _patch(_hr73, "_set_rr", lambda g, row: None)
        _patch(_hr73, "_finish", lambda remote, recs, now, rb: finished.append(now))
        with _p9.app_context():
            for now, detail in detail_at:
                _patch(_hr73, "safe_start", lambda remote, g, _d=detail: ("wait", _d))
                _hr73._act(NS(id=-73), [(gs, d)], now, rollback)
    return d, finished


_DAY73 = _rw73.INFLIGHT_GIVE_UP
_inf_held73 = _held73([(1000, "inflight"), (1000 + _DAY73 - 1, "inflight")])
_inf_gone73 = _held73([(1000, "inflight"), (1000 + 3700, "inflight"), (1000 + _DAY73, "inflight")])
_inf_rb73 = _held73([(1000, "inflight"), (1000 + _DAY73, "inflight")], rollback=True)
# A "window" tick did not read the inflight state, so it keeps the day's clock (part76 holds the
# realistic tick stream and the outcome that does restart it).
_inf_reset73 = _held73([(1000, "inflight"), (2000, "window"), (1000 + _DAY73, "inflight")])
check("reboot: a start held by a LinuxGSM command in flight stays pending past the hour, but not for "
      "ever: a day on, the row is failed with that reason and the plan finishes (the clock was reset on "
      "every tick, and the plan held every later reboot of the host)",
      _DAY73 == 86400 and _inf_held73[0]["restore"] == "pending" and _inf_held73[1] == []
      and _inf_gone73[0]["restore"] == "failed" and "LinuxGSM command" in _inf_gone73[0]["result"]
      and "called off" not in _inf_gone73[0]["result"] and _inf_gone73[1] == [1000 + _DAY73]
      and "called off" in _inf_rb73[0]["result"] and _inf_reset73[0]["restore"] == "failed",
      repr((_inf_held73, _inf_gone73, _inf_rb73, _inf_reset73)))


def _silent_rb73(at, now):
    gs = NS(id=-74, lgsm_name="p73srv", short_name="p73", name="p73")
    d = {"restore": "pending", "owner": "none", "stop": "stopped", "act": "now", "at": at}
    cleared = []
    with _patched():
        _patch(_hr73, "_records", lambda rows: [(gs, d)])
        _patch(_hr73, "_set_rr", lambda g, row: None)
        _patch(_hr73, "_clear", lambda remote, recs, why, notify=True: cleared.append(why))
        _patch(_hr73, "_host_label", lambda remote: "p73host")
        _patch(_smh73, "host_boot_identity", lambda r: None)
        with _p9.app_context():
            res = _hr73.restore_host(NS(id=-74), [gs], now)
    return res, cleared


_rb_week73 = _silent_rb73(1000, 1000 + _hr73.STALE_PLAN + 1)
_rb_day73 = _silent_rb73(1000, 1000 + 86400)
check("reboot: a rollback whose host stays silent past STALE_PLAN has its plan dropped, as any other "
      "plan's is (it kept the 15 s tick, an SSH timeout each, for good); a shorter silence still holds "
      "the clock",
      _rb_week73[0] is False and len(_rb_week73[1]) == 1 and "a week" in _rb_week73[1][0]
      and _rb_day73 == (True, []), repr((_rb_week73, _rb_day73)))


# ── A02 leads: the update card's merge-base and the test branch's rev-parse ──────────────────────
def _upd73(branch, merge_base_rc=0, rev_parse=("f" * 40, "", 0)):
    asked = []

    def _git(args, timeout=45):
        if args[:2] == ["rev-list", "--first-parent"] and "--count" in args:
            return ("3", "", 0)
        if args[:2] == ["rev-list", "--first-parent"]:
            return ("a" * 40 + "\n" + "b" * 40, "", 0)
        if args[:2] == ["rev-parse", "--short"]:
            return ("abc1234", "", 0)
        if args[0] == "rev-parse":
            return rev_parse
        if args[:2] == ["merge-base", "--is-ancestor"]:
            # The on-branch question names the fetched ref; each walked commit's names a sha.
            return ("", "", merge_base_rc if args[3].startswith("refs/") else 0)
        return ("", "", 0)
    with _patched():
        _patch(_so73, "_git", _git)
        _patch(_so73, "_is_git_checkout", lambda: True)
        _patch(_so73, "panel_version", lambda: "2026.10.1")
        _patch(_so73, "_tracked_branch", lambda: branch)
        _patch(_so73, "_remote_ci_state", lambda sha: asked.append(sha) or "passing")
        _patch(_so73, "_update_touches_runtime", lambda ref: True)
        _patch(_so73, "_runtime_changelog", lambda *a, **k: [])
        _patch(_so73, "version_for_commit", lambda ref: "2026.10.2")
        _patch(_so73, "github_repo_url", lambda: "")
        return _so73._compute_update_status(), asked


_UNREAD73 = "Couldn't read how far behind the update source this panel is."
_mb_fail73 = _upd73(_so73._DEFAULT_BRANCH, merge_base_rc=128)
_mb_ok73 = _upd73(_so73._DEFAULT_BRANCH, merge_base_rc=0)
_rp_fail73 = _upd73("p73-test", rev_parse=("", "git timed out", -1))
_rp_ok73 = _upd73("p73-test")
check("self-update: a `merge-base --is-ancestor` that failed is not \"not on the branch\" (that turned the "
      "contains-HEAD filter off): no update, and it says the source could not be read; a test branch's "
      "tip that could not be read is not offered as \"\" either; both still work when read",
      _mb_fail73[0].get("message") == _UNREAD73 and _mb_fail73[0].get("update_available") is False
      and _mb_ok73[0].get("update_available") is True
      and _rp_fail73[0].get("message") == _UNREAD73 and _rp_fail73[0].get("update_available") is False
      and _rp_ok73[0].get("target_sha") == "f" * 40,
      repr((_mb_fail73, _mb_ok73, _rp_fail73, _rp_ok73)))


# ── A03 lead: a stored SSH port int() cannot take (REAL infinity) ────────────────────────────────
_INF73 = NS(port=float("inf"))
with _patched():
    _patch(_smh73, "_sshd_current_ports", lambda server: ["2222"])
    try:
        _served73 = _smf73._fwssh_served_ports(_INF73)
    except Exception as _e73:  # noqa: BLE001 - as below
        _served73 = type(_e73).__name__
try:
    _arg73 = _smc73._ssh_port_arg(_INF73)
except ValueError:
    _arg73 = "ValueError"
except Exception as _e73:  # noqa: BLE001 - the class is what the check reads
    _arg73 = type(_e73).__name__
try:
    _sp73 = _smf73._ssh_ports(_INF73)
except Exception as _e73:  # noqa: BLE001 - the old code's OverflowError is what this reads
    _sp73 = type(_e73).__name__
check("ssh port: a port stored as REAL infinity is no extra SSH port to the firewall guards, and ssh's "
      "`-p` refuses it with the ValueError its callers catch (each raised OverflowError past an except "
      "written for TypeError/ValueError)",
      _sp73 == {22} and _served73 == {2222} and _arg73 == "ValueError"
      and _smf73._ssh_ports(NS(port=2022)) == {22, 2022},
      repr((_sp73, _served73, _arg73)))


# ── whole class: a root write or reload whose rc was dropped, then reported as done ──────────────
_bsa_ok73 = _bootstrap51(())
_bsa_w73 = _bootstrap51({("write", "apt-auto-upgrades")})
_bsa_e73 = _bootstrap51({("service-enable-now", ("unattended-upgrades",))})
_AU73 = "automatic security updates were not enabled"
check("bootstrap: automatic security updates whose config write or enable failed are named in a "
      "'finished, but' answer and logged NOT DONE (neither was read, and it said 'complete')",
      _bsa_ok73[0] is True and _AU73 not in str(_bsa_ok73[1])
      and _bsa_w73[0] is False and _AU73 in str(_bsa_w73[1]) and "NOT DONE" in _bsa_w73[2]
      and _bsa_e73[0] is False and _AU73 in str(_bsa_e73[1])
      and all(_CAT73[lg].get(_AU73) for lg in ("es", "fr")),
      repr((_bsa_ok73[:2], _bsa_w73[:2], _bsa_e73[:2])))


def _tsboot73(write_rc):
    with _patched():
        _patch(_smc73, "write_root_file", lambda *a, **k: ("", "disk full" if write_rc else "", write_rc))
        _patch(_smc73, "run_privileged", lambda *a, **k: ("", "", 0))
        _patch(_smh73, "remote_check_tailscale",
               lambda s: {"running": True, "tailscale_ip": "203.0.113.5", "dns_name": "p73"})
        return _smh73.remote_bootstrap_tailscale(NS(name="p73"), auth_key="p73" + "key",
                                                 advertise_routes="192.0.2.0/24")


_tsb_bad73, _tsb_ok73 = _tsboot73(1), _tsboot73(0)
check("tailscale bootstrap: IP forwarding whose sysctl write failed is logged NOT enabled, not "
      "'IP forwarding enabled'; one that took still says enabled",
      "IP forwarding was NOT enabled (disk full)" in _tsb_bad73[2]
      and "IP forwarding enabled" not in _tsb_bad73[2] and "IP forwarding enabled" in _tsb_ok73[2],
      repr((_tsb_bad73[2], _tsb_ok73[2])))


def _hostwl73(reload_rc):
    with _patched():
        _patch(_so73, "panel_fail2ban_status", lambda: {"installed": True})
        _patch(_so73, "_F2B_PANEL_WHITELIST", _os73.path.join(_ROOT73, "p73-no-such-dir", "wl.local"))
        _patch(_so73, "_write_root_file", lambda path, content: ("", "", 0))
        _patch(_so73, "_run_verb", lambda verb, args, **k: ("", "", reload_rc if verb == "f2b-reload" else 0))
        return _so73.ensure_panel_host_whitelist(["203.0.113.5"])


_hwl_bad73, _hwl_ok73 = _hostwl73(1), _hostwl73(0)
check("panel-host whitelist: a fail2ban reload that failed is not 'applied to every jail' (its rc was "
      "dropped, as the remote twin's was)",
      _hwl_bad73[0] is False and "did not reload" in _hwl_bad73[1] and _hwl_ok73[0] is True,
      repr((_hwl_bad73, _hwl_ok73)))


# ── OS Updates: a package upgradable for two architectures ────────────────────────────────────────
_APT73 = "\n".join([
    "Listing...",
    "libx11-6/noble-security 2:1.8.7-1ubuntu0.1 i386 [upgradable from: 2:1.8.7-1build1]",
    "libx11-6/noble-security 2:1.8.7-1ubuntu0.1 amd64 [upgradable from: 2:1.8.7-1build1]",
    "curl/noble-updates 8.5.0-2ubuntu10.6 amd64 [upgradable from: 8.5.0-2ubuntu10.5]",
    "libx11-data/noble-security 2:1.8.7-1ubuntu0.1 all [upgradable from: 2:1.8.7-1build1]",
    "libsdl2-2.0-0/noble-updates 2.30.0+dfsg-1ubuntu3.1 i386 [upgradable from: 2.30.0+dfsg-1build3]",
])
_up73 = _so73.parse_upgradable(_APT73)
_LABELS73 = ["curl", "libsdl2-2.0-0 (i386)", "libx11-6 (amd64)", "libx11-6 (i386)", "libx11-data"]
check("os updates: a package upgradable for amd64 and i386 is two rows that say which (they read as the "
      "same row twice, the arch dropped); sorted by name then arch; a foreign-arch package alone is "
      "labelled, a native or `all` one is not",
      [p.get("label") for p in _up73] == _LABELS73
      and [p.get("arch") for p in _up73] == ["amd64", "i386", "amd64", "i386", "all"]
      and _smh73._parse_upgradable(_APT73) == _up73, repr(_up73))

_us73 = _osu73._update_summary(_up73)
check("os updates: ...the alert quotes the labels and still counts every upgrade (5, 3 security)",
      _us73 == (5, 3, ["libx11-6 (amd64)", "libx11-6 (i386)", "libx11-data"]), repr(_us73))

_rm73 = _read73("static", "js", "remote_manage.js")
_ru73 = _rm73[_rm73.index("function isSecurityPkg"):_rm73.index("// available → enabled")]
_ruv73 = _node47(
    "const el = {};\nconst document = {getElementById: (id) => id === 'update-info' ? el : null};\n"
    "const escapeHtml = (s) => String(s);\nconst setInstallUpdatesState = () => {};\n" + _ru73
    + "renderUpdates({count: 5, packages: " + _json73.dumps(_up73) + "}, '');\n"
    + "console.log(JSON.stringify(el.innerHTML));")
check("os updates: ...and the card shows each row's label, with its count and security count as before",
      _ruv73 is None or (isinstance(_ruv73, str) and "libx11-6 (i386)</span>" in _ruv73
                         and "libx11-6 (amd64)</span>" in _ruv73 and "libx11-data</span>" in _ruv73
                         and " 5 <span>updates available" in _ruv73 and ">3 <span>security" in _ruv73),
      repr(_ruv73))
if _ruv73 is None:
    skip("os updates: the card's rendering", "no node")

check("part73: nothing its routes drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP73_START, repr(_P9_TRIPPED[_TRIP73_START:][:6]))
