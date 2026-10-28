"""Part 82 of the unit suite: the eleventh review's core, system and helper fixes (builder A).

Held here, each against the code path the finding named:

* A changed host key, or a read cut off part-way, is still answered `unreachable: true` (no reading
  was taken), with a `code` saying which: #429 made it false, and the remote Firewall page's
  refresh painted "Inactive", "No open ports yet." and "No IPs are blocked." about a host the panel
  had refused to connect to. The pages show the route's own sentence for those two.
* The no-helper, non-root shell form of a compound verb is elevated whole (`sudo bash -c`): the
  bare `sudo ` prefix elevated only its first command, and Connect Tailscale never got a link.
* The helper's `sudo -l -U` read and the tailnet ping run in the C locale (each is read by its
  English words).

HOW IT RUNS. Routes on part12's Flask app and client (part12 has run), every stub through
_p9_patch and undone in the finally. part12's transport tripwire is armed for the whole part and
read at its end, so "nothing reaches a transport" is checked, not assumed (review 1015c); section 2
puts back the one internal it drives, by name. Page scripts in node.
"""
import json as _json82
import os
import shlex as _shlex82
import subprocess as _sp82  # nosec B404 - only its constants; every run here is a stand-in
from types import SimpleNamespace as NS

from unit.part01 import check, skip
from unit.part05 import _helper, _root
from unit.part47 import _SETTLE47, _cut47, _node47
from unit.part12 import (P9_ADMIN, P9_HOST, _P9_TRIPPED, _p9, _p9_arm, _p9_client, _p9_json, _p9_patch, _p9_patch_sm,
                         _p9_restore_all)
from panel.core import i18n as _i18n82
from panel.db.models import User as _U82, db as _db82
from panel.ops import system_ops as _so82, tailscale_integration as _ts82
from panel.ops.ssh_manager import HostKeyMismatch as _HKM82
from panel.routes import remote_vps as _rv82
from panel.security import privileged as _priv82


def _read82(*parts):
    with open(os.path.join(_root, *parts), encoding="utf-8") as fh:
        return fh.read()


def _try82(fn, *a, **k):
    """Return fn's answer, or ("raised", <class>): a raise is a failed check by name, not a dead part."""
    try:
        return fn(*a, **k)
    except Exception as exc:  # noqa: BLE001 - reported by class, in the check that reads it
        return ("raised", type(exc).__name__)


def _node82(name, prog):
    """Run `prog` in node; its JSON answer, or None (and a SKIP naming `name`) without node."""
    out = _node47(prog)
    if out is None:
        skip(name, "node is not installed here")
    return out


def _as82(lang):
    with _p9.app_context():
        _db82.session.get(_U82, P9_ADMIN).language = lang
        _db82.session.commit()


with _p9.app_context():
    _LANG82_WAS = _db82.session.get(_U82, P9_ADMIN).language

# A minimal DOM: elements by id, created on first use, that keep their text and children.
_DOM82 = (
    "const els = {};\n"
    "function mk(id){ return {id: id, textContent: '', innerHTML: '', className: '', title: '',\n"
    "  style: {}, children: [], classList: {toggle(){}, add(){}, remove(){}},\n"
    "  setAttribute(){}, appendChild(c){ this.children.push(c); return c; }}; }\n"
    "global.window = global; global.MOUNT = ''; global.remoteId = 7; global.REMOTE_ID = 7;\n"
    "global.document = {getElementById: id => els[id] || (els[id] = mk(id)),\n"
    "  createElement: tag => mk(tag), createTextNode: v => ({textContent: String(v)}),\n"
    "  querySelectorAll: () => []};\n"
    "global.t = s => s; global.escapeHtml = s => String(s).replace(/</g, '&lt;');\n"
    "global.toast = () => {}; global.setInstallUpdatesState = () => {};\n"
    "global.renderUpdates = () => {}; global._r18cPaintHostBadge = () => {};\n")

_TRIP82_START = len(_P9_TRIPPED)
_REAL82 = {"_run_verb": _so82._run_verb}
try:
    _p9_arm(who="part82")
    # ════════════════════════════════════════════════════════════════════════════════════════════
    # 1. A changed host key / a cut-off read: unreachable stays true, `code` says which
    # ════════════════════════════════════════════════════════════════════════════════════════════
    def _key82(*_a, **_k):
        raise _HKM82("unit p82: the SSH host key for h has CHANGED")

    def _cut82(*_a, **_k):
        exc = ConnectionError("Command failed: socket closed")
        exc.command_started = True
        raise exc

    def _down82(*_a, **_k):
        raise ConnectionError("timed out")

    _as82("fr")
    _c82 = _p9_client(P9_ADMIN)
    _fw82 = {}
    for _k82, _fn82 in (("key", _key82), ("cut", _cut82), ("down", _down82)):
        _p9_patch(_rv82, "remote_ufw_status", _fn82)
        _r82 = _c82.get("/api/remote/%d/firewall" % P9_HOST)
        _fw82[_k82] = (_r82.status_code, _p9_json(_r82))
    _p9_patch_sm("remote_os_check_updates", _key82)
    _r82 = _c82.get("/api/remote/%d/check-updates" % P9_HOST)
    _upd82 = (_r82.status_code, _p9_json(_r82))
    _as82(_LANG82_WAS)
    _fr82 = _i18n82.catalog("fr")
    _fr_key82 = _fr82.get("The panel refused to connect: this host's SSH key is not the one it "
                          "trusts. If you reinstalled the host, use Re-trust host key on its page.")
    _fr_cut82 = _fr82.get("The host stopped answering while the command was running, so it may "
                          "have run. Check the host before trying again.")
    check("unreachable: a changed host key on the remote Firewall refresh is still flagged "
          "unreachable (no reading was taken), with code host_key_mismatch and the Re-trust "
          "sentence in the viewer's language",
          _fw82["key"][0] == 200 and _fw82["key"][1].get("unreachable") is True
          and _fw82["key"][1].get("code") == "host_key_mismatch" and bool(_fr_key82)
          and _fw82["key"][1].get("message") == _fr_key82, repr(_fw82["key"]))
    check("unreachable: ...and so is a read cut off part-way (code command_started), and a host "
          "that did not answer (code host_unreachable); check-updates answers the same",
          _fw82["cut"][1].get("unreachable") is True and _fw82["cut"][1].get("code") == "command_started"
          and bool(_fr_cut82) and _fw82["cut"][1].get("message") == _fr_cut82
          and _fw82["down"][1].get("unreachable") is True
          and _fw82["down"][1].get("code") == "host_unreachable"
          and _upd82[1].get("unreachable") is True and _upd82[1].get("code") == "host_key_mismatch",
          repr((_fw82, _upd82)))

    # The pages, fed exactly what the route answered.
    _fwjs82 = _read82("static", "js", "remote_firewall.js")
    _body82 = _json82.dumps(_fw82["key"][1])
    _fw_out82 = _node82("remote_firewall.js: a refresh answered with a changed host key", _DOM82 + _SETTLE47 + (
        "global.fetch = () => Promise.resolve({json: () => Promise.resolve(%s)});\n"
        # The settings row's own read (fw-more): not this check's subject.
        "global.refreshFwSettings = () => {};\n"
        "%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n"
        "(async () => { refreshFirewall(); await settle();\n"
        "  const txt = id => els[id].children.map(c => c.textContent).join('|');\n"
        "  console.log(JSON.stringify({badge: els['ufw-badge'].textContent, rules: txt('rules-list'),\n"
        "    blocks: txt('blocks-list'), count: els['rules-count'].textContent})); })();\n"
    ) % (_body82, _cut47(_fwjs82, "function refreshFirewall("), _cut47(_fwjs82, "function _fwUnlisted("),
         _cut47(_fwjs82, "function _fwUnreadWhy("),
         # The status card's repaint and the reason both it and the lists read (review 1015c).
         _cut47(_fwjs82, "function _fwHostSaid("), _cut47(_fwjs82, "function _fwStatusNote("),
         _cut47(_fwjs82, "function _fwRenderRules("), _cut47(_fwjs82, "function _fwRenderBlocks("),
         # The not-a-reading guard refreshFirewall calls first (review 1015d).
         _cut47(_fwjs82, "function _r23c_fwNotRead(")))
    if _fw_out82 is not None:
        check("remote firewall page: a refresh answered with a changed host key reads 'Unknown' and "
              "says the route's Re-trust sentence on both lists (it read Inactive, 'No open ports "
              "yet.' and 'No IPs are blocked.')",
              _fw_out82.get("badge") == "Unknown" and _fw_out82.get("rules") == _fr_key82
              and _fw_out82.get("blocks") == _fr_key82 and _fw_out82.get("count") == "—",
              repr(_fw_out82))

    _rmjs82 = _read82("static", "js", "remote_manage.js")
    _rm_out82 = _node82("remote_manage.js: check-updates and the live card on a changed host key", _DOM82 + _SETTLE47 + (
        "let answer = null;\n"
        "global.fetch = () => Promise.resolve({json: () => Promise.resolve(answer)});\n"
        "var _updatesAsked = false;\n%s\n%s\n"
        "(async () => {\n"
        "  answer = %s; checkUpdates(); await settle();\n"
        "  answer = Object.assign({error: %s}, %s); pollLive(); await settle();\n"
        "  const plain = els['update-info'].innerHTML, live = els['live-stale'].textContent;\n"
        "  answer = %s; checkUpdates(); await settle();\n"
        "  console.log(JSON.stringify({upd: plain, live: live, down: els['update-info'].innerHTML})); })();\n"
    ) % (_cut47(_rmjs82, "function checkUpdates("),
         # the order guard pollLive calls (review 1017a): its counters' line and the guard
         _rmjs82[_rmjs82.index("var _r30c_liveSent"):].split("\n", 1)[0] + "\n"
         + _cut47(_rmjs82, "function _r30c_liveOld(") + "\n" + _cut47(_rmjs82, "function pollLive("),
         _json82.dumps(_upd82[1]), _json82.dumps(_fr_key82), _json82.dumps(_upd82[1]),
         _json82.dumps(_fw82["down"][1])))
    if _rm_out82 is not None:
        check("remote manage page: check-updates and the live card say the changed-host-key "
              "sentence (they said 'apt may be busy. Try again' / 'the last read failed'), and a "
              "host that did not answer still reads as unreachable",
              _fr_key82 is not None and _fr_key82 in (_rm_out82.get("upd") or "")
              and _rm_out82.get("live") == _fr_key82
              and "Couldn't reach the host" in (_rm_out82.get("down") or ""), repr(_rm_out82))

    # ════════════════════════════════════════════════════════════════════════════════════════════
    # 2. No helper, not root: a compound verb's shell form is elevated whole
    # ════════════════════════════════════════════════════════════════════════════════════════════
    _pop82 = []

    class _Sub82:
        PIPE, DEVNULL, TimeoutExpired = _sp82.PIPE, _sp82.DEVNULL, _sp82.TimeoutExpired

        @staticmethod
        def Popen(argv, **k):
            _pop82.append((argv, k))
            return NS(pid=0)

    class _Euid82:
        """os, with geteuid answering `uid`."""

        def __init__(self, uid):
            self._uid = uid

        def geteuid(self):
            return self._uid

        def __getattr__(self, name):
            return getattr(os, name)

    _p9_patch(_so82, "subprocess", _Sub82)
    _p9_patch(_so82, "_run_verb", _REAL82["_run_verb"])     # driven here, onto _Sub82
    _p9_patch(_so82, "_collect_verb_output", lambda p, cmd, timeout, *a, **k: ("", "", 0))
    _p9_patch(_so82, "_helper_present", lambda: False)
    _p9_patch(_so82, "os", _Euid82(1000))
    _p9_patch(_ts82, "get_tailscale_info", lambda force_refresh=False: NS(running=False))
    _up82 = _try82(_ts82.tailscale_up_local)
    _up_pop82, _pop82[:] = list(_pop82), []
    _so82._run_verb("ufw-status", ["numbered"], timeout=5)
    _simple_pop82, _pop82[:] = list(_pop82), []
    _want82 = _priv82.remote_command("tailscale-up-login", ["yes", "-"], merge_stderr=False)
    _got82 = _up_pop82[0][0] if _up_pop82 else ""
    check("system_ops: Connect Tailscale on a non-root panel host with no helper runs the verb's "
          "compound shell form whole under `sudo bash -c` (a bare `sudo ` elevated only its `rm`, "
          "and `tailscale up` could not write into /run)",
          isinstance(_got82, str) and _shlex82.split(_got82)[:3] == ["sudo", "bash", "-c"]
          and _shlex82.split(_got82)[3:] == [_want82] and len(_up_pop82) == 1
          and isinstance(_up82, tuple) and _up82[0] is False, repr((_up82, _up_pop82)))
    check("system_ops: ...while a tool's own argv rendering keeps the bare `sudo <tool>` (a narrow "
          "sudoers grant allows the tool, not bash)",
          bool(_simple_pop82)
          and _simple_pop82[0][0] == "sudo " + _priv82.remote_command("ufw-status", ["numbered"]),
          repr(_simple_pop82))

    # ════════════════════════════════════════════════════════════════════════════════════════════
    # 3. The helper's `sudo -l -U` and the tailnet ping are read in the C locale
    # ════════════════════════════════════════════════════════════════════════════════════════════
    _sl_saved82 = (_helper._sudo_list_binaries, _helper.subprocess)
    _sl_env82 = []

    def _sl_run82(argv, **k):
        # A German host answers in German unless asked in C: "darf die folgenden Befehle".
        env = k.get("env")
        _sl_env82.append(env)
        c = env is not None and env.get("LC_ALL") in ("C", "C.UTF-8") and not env.get("LANGUAGE")
        said = ("User deploy may run the following commands:" if c
                else "Benutzer deploy darf die folgenden Befehle ausführen:")
        return NS(stdout=said.encode(), stderr=b"", returncode=0)
    try:
        _helper._sudo_list_binaries = lambda: ["/usr/bin/sudo.ws", "/usr/bin/sudo"]
        _helper.subprocess = NS(run=_sl_run82)
        _sl82 = _helper._sudo_lists_rules("deploy")
    finally:
        _helper._sudo_list_binaries, _helper.subprocess = _sl_saved82
    check("helper: `sudo -l -U` is asked in the C locale on every sudo present, so a listed rule "
          "reads as one on a host that is not in English",
          _sl82 is True and len(_sl_env82) == 2, repr((_sl82, _sl_env82)))

    _ping82 = []

    def _ping_run82(argv, **k):
        _ping82.append(k.get("env"))
        c = (k.get("env") or {}).get("LC_ALL") == "C.UTF-8" and (k.get("env") or {}).get("LANGUAGE") == ""
        return NS(returncode=0, stdout="64 bytes from peer82.tail1234.ts.net: icmp_seq=1 ttl=64 %s=12.5 ms\n"
                  % ("time" if c else "Zeit"), stderr="")
    _p9_patch(_ts82, "subprocess", NS(run=_ping_run82))
    _pr82 = _try82(_ts82.check_peer_reachability, "peer82.tail1234.ts.net")
    check("tailscale: the tailnet ping runs in C.UTF-8 with an empty LANGUAGE, so its `time=` is "
          "read on a host that is not in English (it read 0 ms)",
          isinstance(_pr82, dict) and _pr82.get("latency_ms") == 12.5, repr((_pr82, _ping82)))
finally:
    _p9_restore_all()
    _as82(_LANG82_WAS)
check("part82: nothing it drove reached a real transport (every host call was stubbed)",
      len(_P9_TRIPPED) == _TRIP82_START, repr(_P9_TRIPPED[_TRIP82_START:][:6]))
