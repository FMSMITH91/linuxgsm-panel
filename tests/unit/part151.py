"""Part 151 of the unit suite: the Config tab's LinuxGSM settings form (cmpc).

Each setting is shown with LinuxGSM's own help from the comments above it in _default.cfg, the
heading it sits under, a link to its docs.linuxgsm.com page, and the file its value comes from
(panel/services/lgsm_cfg_form.py). Held here:

* the help parser, on a _default.cfg in LinuxGSM's own comment format;
* the read: every setting says which of the five files its value comes from, and an empty
  _default.cfg is said as that rather than read as "no settings";
* secrets: a viewer who may not see them never receives one, through the route too;
* the writes: a form save writes ONLY the changed line of <instance>.cfg, never _default.cfg; the
  file editor refuses to save an instance's _default.cfg (LinuxGSM puts its own copy back); and a
  value can never break out of its double quotes when LinuxGSM sources the file in bash.

HOW IT RUNS. Pure helpers with their host reads stubbed; routes on part12's app with its transport
tripwire armed; bash sources a written cfg in a temporary directory; the page script in node.
"""
import base64 as _b64_cmpc_
import json as _json_cmpc_
import os
import re
import shutil as _shutil_cmpc_
import subprocess as _sp_cmpc_  # nosec B404 - bash sources a cfg this part wrote, fixed argv
import tempfile as _tf_cmpc_
from types import SimpleNamespace as _NS_cmpc_

from unit.part01 import check, skip
from unit.part05 import _root
from unit.part12 import (P9_ADMIN, P9_GS, _p9_arm, _p9_audit, _p9_client, _p9_json, _p9_patch,
                         _p9_restore_all)
from unit.part47 import _cut47, _node47
from panel.ops.ssh_manager import _core as _smc_cmpc_, files as _files_cmpc_
from panel.routes import server_detail as _sd_cmpc_, server_files as _sf_cmpc_
from panel.services import lgsm_cfg_form as _form_cmpc_

# A _default.cfg in LinuxGSM's own comment format (lgsm/config-default/config-lgsm/*/_default.cfg).
_DEFAULT_cmpc_ = """##################################
######## Default Settings ########
##################################
# DO NOT EDIT, ANY CHANGES WILL BE OVERWRITTEN!

#### Game Server Settings ####

## Predefined Parameters | https://docs.linuxgsm.com/configuration/start-parameters
ip="0.0.0.0"
port="27015"
rconpassword="CHANGE_ME"

## Game Server Login Token (GSLT): Required
# GSLT is required for running a public server.
# More info: https://docs.linuxgsm.com/steamcmd/gslt
gslt=""

## Workshop Parameters | https://developer.valvesoftware.com/wiki/Workshop
# To get an API key visit - https://steamcommunity.com/dev/apikey
wsapikey=""

## Server Parameters | https://docs.linuxgsm.com/configuration/start-parameters#additional-parameters
startparameters="-ip ${ip} -port ${port}"

#### LinuxGSM Settings ####

## Notification Alerts
# (on|off)

# Discord Alerts | https://docs.linuxgsm.com/alerts/discord
discordalert="off"
discordwebhook="webhook"

# Alert on Start/Stop/Restart
statusalert="off"

## Stop Mode | https://docs.linuxgsm.com/features/stop-mode
# 1: tmux kill
# 2: CTRL+c
# https://docs.linuxgsm.com/features/stop-mode#modes
stopmode="2"
querymode="2"

# Odd | https://docs.linuxgsm.com/a"onmouseover=alert(1)
oddone="x"
"""
_H_cmpc_ = _form_cmpc_.parse_help(_DEFAULT_cmpc_)


def _h_cmpc_(key):
    return (_H_cmpc_.get(key) or {}).get("heading"), (_H_cmpc_.get(key) or {}).get("docs"), \
        (_H_cmpc_.get(key) or {}).get("help")


check("cfg form: a setting under `## Heading | docs url` gets that heading and its docs page",
      _h_cmpc_("port") == ("Predefined Parameters", "https://docs.linuxgsm.com/configuration/start-parameters", ""),
      repr(_h_cmpc_("port")))
check("cfg form: the comments directly above a setting are its help; a link in them is its docs page "
      "and a `## Heading:` with no link still names the heading",
      _h_cmpc_("gslt") == ("Game Server Login Token (GSLT): Required", "https://docs.linuxgsm.com/steamcmd/gslt",
                           "GSLT is required for running a public server.\n"
                           "More info: https://docs.linuxgsm.com/steamcmd/gslt"), repr(_h_cmpc_("gslt")))
check("cfg form: a link that is not LinuxGSM's docs is never made a link (it stays in the help text)",
      _h_cmpc_("wsapikey") == ("Workshop Parameters", "",
                               "To get an API key visit - https://steamcommunity.com/dev/apikey"),
      repr(_h_cmpc_("wsapikey")))
check("cfg form: a `# Sub-heading | url` covers the settings under it until a blank line, and the "
      "`## Heading` above takes over after it",
      _h_cmpc_("discordwebhook") == ("Discord Alerts", "https://docs.linuxgsm.com/alerts/discord", "")
      and _h_cmpc_("statusalert") == ("Notification Alerts", "", "Alert on Start/Stop/Restart"),
      repr((_h_cmpc_("discordwebhook"), _h_cmpc_("statusalert"))))
check("cfg form: a comment that is only a link becomes the docs link (the setting's own, before the "
      "heading's), not help text; the next setting keeps the heading but not that help",
      _h_cmpc_("stopmode") == ("Stop Mode", "https://docs.linuxgsm.com/features/stop-mode#modes",
                               "1: tmux kill\n2: CTRL+c")
      and _h_cmpc_("querymode") == ("Stop Mode", "https://docs.linuxgsm.com/features/stop-mode", ""),
      repr((_h_cmpc_("stopmode"), _h_cmpc_("querymode"))))
check("cfg form: a docs link with a quote in it is not a link (it could not leave the page's href)",
      _h_cmpc_("oddone")[1] == "", repr(_h_cmpc_("oddone")))
check("cfg form: the banner and the (on|off) note above a blank line are nobody's help",
      _h_cmpc_("ip")[2] == "" and _h_cmpc_("discordalert")[2] == "", repr((_h_cmpc_("ip"), _h_cmpc_("discordalert"))))


# ── The read: help on every setting, and the file each value comes from ─────────────────────────
def _frames_cmpc_(**texts):
    """lgsm_read_config's framed answer, every frame present, as the transport returns it (stripped)."""
    out = ""
    for tag in ("DEFAULT", "COMMON", "SECRETS_COMMON", "SECRETS_INSTANCE", "INSTANCE"):
        enc = _b64_cmpc_.b64encode(texts.get(tag, "").encode()).decode()
        out += "__LGSMP_%s_B__%s__LGSMP_%s_E__" % (tag, enc, tag)
    return out.strip(), "", 0


_LAYERS_cmpc_ = dict(DEFAULT=_DEFAULT_cmpc_, COMMON='port="27016"\nstopmode="3"\n',
                     SECRETS_COMMON='discordwebhook="https://discord.example.test/api/webhooks/1/common"\n',
                     INSTANCE='# mine\nport="27017"\nrconpassword="hunter2-151"\n',
                     SECRETS_INSTANCE='gslt="GSLT151SECRET"\n')
_saved_rc_cmpc_ = _smc_cmpc_.run_command
try:
    _smc_cmpc_.run_command = lambda s, c, **k: _frames_cmpc_(**_LAYERS_cmpc_)
    _read_cmpc_ = _files_cmpc_.lgsm_read_config(_NS_cmpc_(), "csgoserver", "csgoserver")
    _smc_cmpc_.run_command = lambda s, c, **k: _frames_cmpc_(INSTANCE='port="1"\n')
    _nodef_cmpc_ = _files_cmpc_.lgsm_read_config(_NS_cmpc_(), "csgoserver", "csgoserver")
finally:
    _smc_cmpc_.run_command = _saved_rc_cmpc_
_by_cmpc_ = {s["key"]: s for g in _read_cmpc_.get("groups") or () for s in g["settings"]}
_layers_seen_cmpc_ = {k: (_by_cmpc_.get(k) or {}).get("layer_file")
                      for k in ("ip", "port", "stopmode", "discordwebhook", "rconpassword", "gslt")}
check("cfg form: each setting names the file its value comes from, the LAST one LinuxGSM sources "
      "(_default < common < secrets-common < instance < secrets-instance)",
      _layers_seen_cmpc_ == {"ip": "_default.cfg", "port": "csgoserver.cfg", "stopmode": "common.cfg",
                             "discordwebhook": "secrets-common.cfg", "rconpassword": "csgoserver.cfg",
                             "gslt": "secrets-csgoserver.cfg"}, repr(_layers_seen_cmpc_))
check("cfg form: the read carries each setting's help, heading and docs link",
      (_by_cmpc_.get("gslt") or {}).get("docs") == "https://docs.linuxgsm.com/steamcmd/gslt"
      and (_by_cmpc_.get("stopmode") or {}).get("help") == "1: tmux kill\n2: CTRL+c"
      and (_by_cmpc_.get("discordalert") or {}).get("heading") == "Discord Alerts"
      and _read_cmpc_.get("default_missing") is False, repr(_by_cmpc_.get("gslt")))
check("cfg form: a read whose _default.cfg is absent or empty says so (default_missing), with no "
      "error and the raw instance cfg still there, instead of an empty form that reads as 'no settings'",
      _nodef_cmpc_.get("default_missing") is True and not _nodef_cmpc_.get("groups")
      and _nodef_cmpc_.get("error") is None and _nodef_cmpc_.get("raw") == 'port="1"\n', repr(_nodef_cmpc_))


# ── Secrets: never sent to a viewer who may not see them ────────────────────────────────────────
_SECRETS_cmpc_ = ("hunter2-151", "GSLT151SECRET", "discord.example.test")


def _view_cmpc_(sees):
    """form_view of a fresh copy of the read, for an actor who sees secrets or not (the real predicate)."""
    saved = _sd_cmpc_.has_permission
    try:
        _sd_cmpc_.has_permission = lambda actor, perm: sees
        return _form_cmpc_.form_view(_json_cmpc_.loads(_json_cmpc_.dumps(_read_cmpc_)),
                                     _NS_cmpc_(is_superadmin=False, id=151))
    finally:
        _sd_cmpc_.has_permission = saved


_hid_cmpc_, _seen_cmpc_ = _view_cmpc_(False), _view_cmpc_(True)
_hid_txt_cmpc_ = _json_cmpc_.dumps(_hid_cmpc_)
_hby_cmpc_ = {s["key"]: s for g in _hid_cmpc_.get("groups") or () for s in g["settings"]}
check("cfg form: a viewer who may not see secrets gets no password, token, GSLT or webhook anywhere in "
      "the reply (not in the fields, the curated list or the raw instance cfg)",
      not any(x in _hid_txt_cmpc_ for x in _SECRETS_cmpc_) and _hid_cmpc_.get("raw") == ""
      and _hid_cmpc_.get("raw_hidden") is True,
      [x for x in _SECRETS_cmpc_ if x in _hid_txt_cmpc_])
check("cfg form: ...each secret field is the mask, marked read-only (so a Save never posts the mask "
      "back), the start line too, and an ordinary setting is left as it is",
      all((_hby_cmpc_.get(k) or {}).get("value") == _form_cmpc_.MASK and (_hby_cmpc_.get(k) or {}).get("masked")
          for k in ("rconpassword", "gslt", "discordwebhook", "wsapikey", "startparameters"))
      and (_hby_cmpc_.get("port") or {}).get("value") == "27017" and not (_hby_cmpc_.get("port") or {}).get("masked"),
      repr({k: (_hby_cmpc_.get(k) or {}).get("value") for k in ("rconpassword", "port", "startparameters")}))
check("cfg form: ...while a viewer who can open the configs gets the read as it was",
      _seen_cmpc_ == _read_cmpc_ and all(x in _json_cmpc_.dumps(_seen_cmpc_) for x in _SECRETS_cmpc_[:2]))
check("cfg form: a caller that is not a panel user is masked (the predicate fails closed)",
      "hunter2-151" not in _json_cmpc_.dumps(_form_cmpc_.form_view(
          _json_cmpc_.loads(_json_cmpc_.dumps(_read_cmpc_)), _NS_cmpc_())))

# The caller: GET /config goes through form_view.
try:
    _p9_arm(who="part151")
    _p9_patch(_sf_cmpc_, "lgsm_read_config", lambda *a: _json_cmpc_.loads(_json_cmpc_.dumps(_read_cmpc_)))
    _p9_patch(_sd_cmpc_, "_dtl_sees_secrets", lambda actor: False)
    _rg_cmpc_ = _p9_client(P9_ADMIN).get("/api/server/%d/config" % P9_GS)
    _p9_patch(_sd_cmpc_, "_dtl_sees_secrets", lambda actor: True)
    _rs_cmpc_ = _p9_client(P9_ADMIN).get("/api/server/%d/config" % P9_GS)
finally:
    _p9_restore_all()
check("config route: the reply goes through the secrets mask (a viewer it keeps them from gets none; "
      "one who may see them gets them)",
      _rg_cmpc_.status_code == 200 and not any(x in _rg_cmpc_.get_data(as_text=True) for x in _SECRETS_cmpc_)
      and _rs_cmpc_.status_code == 200 and "GSLT151SECRET" in _rs_cmpc_.get_data(as_text=True),
      repr((_rg_cmpc_.status_code, _rg_cmpc_.get_data(as_text=True)[:200])))


# ── Writes: only the instance cfg's own line; never _default.cfg ────────────────────────────────
_writes_cmpc_ = []


def _capture_cmpc_(server, user, path, content, selfname):
    _writes_cmpc_.append((path, content.decode() if isinstance(content, bytes) else content))
    return True, ""


try:
    _p9_arm(who="part151")
    _p9_patch(_files_cmpc_, "_read_instance_cfg_lines",
              lambda *a, **k: ["# my notes", 'port="27017"', "# keep me", 'maxplayers="10"'])
    _p9_patch(_files_cmpc_, "_write_file_as_user", _capture_cmpc_)
    _p9_patch(_sf_cmpc_, "_write_refused", lambda gs, action, detail="": None)
    _rp_cmpc_ = _p9_json(_p9_client(P9_ADMIN).post("/api/server/%d/config" % P9_GS,
                                                    json={"settings": {"port": "27020"}}))
    _ws_cmpc_ = list(_writes_cmpc_)
    _writes_cmpc_.clear()
    _rd_cmpc_ = _p9_json(_p9_client(P9_ADMIN).post("/api/server/%d/file" % P9_GS, json={
        "path": "lgsm/config-lgsm/csgoserver/_default.cfg", "content": 'port="1"\n'}))
    _rd2_cmpc_ = _p9_json(_p9_client(P9_ADMIN).post("/api/server/%d/file" % P9_GS, json={
        "path": "./lgsm/config-lgsm/other/../csgoserver/_default.cfg", "content": 'port="1"\n'}))
    _rda_cmpc_ = _p9_audit("edit_file")
    _wd_cmpc_ = list(_writes_cmpc_)
    _rok_cmpc_ = _p9_json(_p9_client(P9_ADMIN).post("/api/server/%d/file" % P9_GS, json={
        "path": "lgsm/config-default/config-lgsm/csgoserver/_default.cfg.notes", "content": "x\n"}))
finally:
    _p9_restore_all()
_inst_cmpc_ = [p for p, _ in _ws_cmpc_]

check("cfg form save: writes ONLY <instance>.cfg — never _default.cfg — changing the one line and "
      "keeping every other line and comment",
      _rp_cmpc_.get("success") is True and len(_ws_cmpc_) == 1
      and re.search(r"/lgsm/config-lgsm/([^/]+)/\1\.cfg\Z", _inst_cmpc_[0]) is not None
      and _ws_cmpc_[0][1] == '# my notes\nport="27020"\n# keep me\nmaxplayers="10"\n',
      repr((_rp_cmpc_, _ws_cmpc_)))
check("file editor: saving an instance's _default.cfg is refused with the reason (LinuxGSM puts its "
      "own copy back) and nothing is written, however the path is spelled; the audit row says why",
      _rd_cmpc_.get("success") is False and _rd_cmpc_.get("message") == _files_cmpc_.CMPC_DEFAULT_CFG_REFUSED
      and _rd2_cmpc_.get("success") is False and _wd_cmpc_ == []
      and _sf_cmpc_._audit_safe(_files_cmpc_.CMPC_DEFAULT_CFG_REFUSED) in getattr(_rda_cmpc_, "detail", ""),
      repr((_rd_cmpc_, _rd2_cmpc_, _wd_cmpc_, getattr(_rda_cmpc_, "detail", None))))
check("file editor: ...while another file there still saves", _rok_cmpc_.get("success") is True, repr(_rok_cmpc_))


# ── Injection: a value never breaks out of its double quotes when bash sources the file ─────────
_VALUES_cmpc_ = {
    "a1": 'say "hi"', "a2": "$(touch PWNED1)", "a3": "`touch PWNED2`", "a4": "ends with \\",
    "a5": 'x\ninjected="1"', "a6": "$1x and $", "a7": "${a8:-$(touch PWNED3)}", "a8": "$((6*7))",
    "a9": "\\$(touch PWNED4)", "b1": "-port ${port}",
}
_lines_cmpc_ = ['port="27015"']
_files_cmpc_._apply_cfg_updates(_lines_cmpc_, _VALUES_cmpc_)
_bash_cmpc_ = _shutil_cmpc_.which("bash")
if not _bash_cmpc_:
    skip("cfg form: values cannot break out of their quotes", "bash is not installed here")
else:
    _tmp_cmpc_ = _tf_cmpc_.mkdtemp(prefix="cmpc151-")
    try:
        with open(os.path.join(_tmp_cmpc_, "inst.cfg"), "w", encoding="utf-8") as _fh_cmpc_:
            _fh_cmpc_.write("\n".join(_lines_cmpc_) + "\n")
        _keys_cmpc_ = sorted(_VALUES_cmpc_) + ["injected"]
        _r_cmpc_ = _sp_cmpc_.run(  # nosec B603 - fixed argv; the cfg is this part's own fixture
            [_bash_cmpc_, "--norc", "--noprofile", "-c",
             "source ./inst.cfg && printf '%s\\0' " + " ".join('"${%s-UNSET}"' % k for k in _keys_cmpc_)],
            cwd=_tmp_cmpc_, capture_output=True, text=True, timeout=20, check=False, env={"PATH": "/usr/bin:/bin"})
        _got_cmpc_ = dict(zip(_keys_cmpc_, _r_cmpc_.stdout.split("\0")))
        _ran_cmpc_ = [f for f in os.listdir(_tmp_cmpc_) if f.startswith("PWNED")]
    finally:
        _shutil_cmpc_.rmtree(_tmp_cmpc_, ignore_errors=True)
    _want_cmpc_ = dict(_VALUES_cmpc_, a5='x injected="1"', b1="-port 27015", injected="UNSET")
    check("cfg form: a value with a quote, $(…), a backtick, a trailing backslash, $1, $((…)) or a line "
          "break is exactly that text once LinuxGSM sources the cfg in bash — nothing runs, no second "
          "setting appears — and a plain ${name} reference stays live",
          _r_cmpc_.returncode == 0 and _ran_cmpc_ == [] and _got_cmpc_ == _want_cmpc_,
          repr((_r_cmpc_.returncode, _r_cmpc_.stderr[:200], _ran_cmpc_,
                {k: v for k, v in _got_cmpc_.items() if _want_cmpc_.get(k) != v})))
    _back_cmpc_ = _files_cmpc_._parse_cfg("\n".join(_lines_cmpc_))
    check("cfg form: ...and the form reads back what was typed (a line break as a space), so a second "
          "save does not escape the escapes",
          all(_back_cmpc_.get(k) == (v.replace("\n", " ")) for k, v in _VALUES_cmpc_.items()),
          repr({k: _back_cmpc_.get(k) for k in _VALUES_cmpc_ if _back_cmpc_.get(k) != _VALUES_cmpc_[k]}))


# ── The page: LinuxGSM's text is escaped and only a docs.linuxgsm.com page is linked ────────────
_SF_cmpc_ = open(os.path.join(_root, "static", "js", "server_files.js"), encoding="utf-8").read()
_out_cmpc_ = _node47(
    "function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')"
    ".replace(/\"/g,'&quot;').replace(/'/g,'&#39;'); }\n"
    + "var _CMPC_LAYER_CLS = {};\n"
    + "".join(_cut47(_SF_cmpc_, h) + "\n" for h in ("function _cmpcDocsOk(", "function _cmpcHelpHtml(",
                                                     "function fieldHtml("))
    + "const base = {key: 'k', value: 'v', default: '', layer: 'default', layer_file: '_default.cfg', heading: ''};\n"
    + "console.log(JSON.stringify({\n"
    + "  bad: fieldHtml(Object.assign({}, base, {help: '<img src=x onerror=alert(1)>', docs: 'javascript:alert(1)'})),\n"
    + "  evil: fieldHtml(Object.assign({}, base, {docs: 'https://docs.linuxgsm.com.example.test/x'})),\n"
    + "  good: fieldHtml(Object.assign({}, base, {help: 'one\\ntwo', docs: 'https://docs.linuxgsm.com/alerts/discord'})),\n"
    + "  masked: fieldHtml(Object.assign({}, base, {masked: true}))}));\n")
if _out_cmpc_ is None:
    skip("cfg form page: help escaped, only LinuxGSM docs linked", "node is not installed here")
else:
    check("cfg form page: LinuxGSM's help is escaped text, and no link is made to anything but a "
          "docs.linuxgsm.com page",
          "<img" not in _out_cmpc_.get("bad", "<img") and "href" not in _out_cmpc_.get("bad", "href")
          and "href" not in _out_cmpc_.get("evil", "href")
          and 'href="https://docs.linuxgsm.com/alerts/discord"' in _out_cmpc_.get("good", "")
          and "<details" in _out_cmpc_.get("good", ""), repr(_out_cmpc_)[:400])
    check("cfg form page: a masked field is read-only", " readonly>" in _out_cmpc_.get("masked", ""),
          repr(_out_cmpc_.get("masked")))
