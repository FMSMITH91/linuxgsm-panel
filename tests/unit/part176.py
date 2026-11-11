r"""Part 176 of the unit suite: the Form view of the game's own config file.

Held here (panel/services/game_config_form.py, panel/routes/game_config_form.py and the page):
* Which files get a form: key=value (.properties, .ini, and .cfg/.txt whose lines are key=value),
  Source/idTech cfg, 7 Days to Die XML (never one declaring a DOCTYPE or an entity) and JSON objects;
  anything else keeps only the raw editor.
* Round trips on sample files modelled on LinuxGSM's default game configs: a save with nothing
  changed is the same text, and a save of changed values differs from the file ONLY in those values
  (comments, order, blank lines, CRLF line endings, spacing and quoting kept byte for byte).
* What a field is: grouped by section, a comment above (or, in XML, beside) it as help, switches
  spelled as the file spells them, numbers, text; secret keys by the rule in the module.
* Every refusal: a file changed since the form was built (the hash), a field that is not there,
  line breaks and control characters, a quote in a cfg value, ; or // in an unquoted one, a space
  at either end of a key=value value, a trailing backslash in .properties, a switch given a third
  value, a number field given text.
* The routes on part12's app with every host call stubbed: the Settings tab's permission, the file
  browser's refusals, the write through the file editor's writer as the game account, the audit row
  naming the changed keys with a secret's values never in it, and the game-config read carrying the
  form.
* `details` naming a config file that is not a .cfg (server.properties, an .ini, .xml or .json).
* The page script in node: a secret's value only in a password input's value property, never in an
  attribute; only changed fields sent, a switch in the file's own spelling.

HOW IT RUNS. No host is reached: read_file, write_file and lgsm_game_config are replaced, part12's
transport tripwire is armed, and the script runs in node through part75's runner.
"""
import json as _json176
import os as _os176

from unit.part01 import _root, check, eq
from unit.part12 import (P9_ADMIN, P9_HOST, P9_VIEWER, _p9_arm, _p9_audit, _p9_audit_count, _p9_client,
                         _p9_delete_server, _p9_new_server, _p9_patch, _p9_patch_sm, _p9_restore_all)
from unit.part75 import _run_js75
from panel.ops.ssh_manager import files as _files176
from panel.routes import game_config_form as _gr176, server_files as _sf176
from panel.services import game_config_form as _g176

# ── samples, modelled on LinuxGSM's default game configs (shortened, values invented) ───────────
sample_source = (
    "// ****************************************************************************\n"
    "// Example Source game\n"
    "// ****************************************************************************\n"
    "\n"
    "// .................................. Basic ................................. //\n"
    "\n"
    "// hostname - Name of the server.\n"
    "hostname \"SERVERNAME\"\n"
    "\n"
    "// rcon_password - Remote console password.\n"
    "rcon_password \"ADMINPASSWORD\"\n"
    "\n"
    "// ................................. Security ................................ //\n"
    "\n"
    "// LAN mode - can't connect from the internet.\n"
    "// Default: sv_lan 0\n"
    "sv_lan 0\n"
    "sv_region -1   // trailing comment\n"
    "// logfile - 0 = disabled, 1 = enabled.\n"
    "logfile 1\n"
    "sv_tags \"\"\n"
    "exec banned_user.cfg\n"
    "writeid\n")
sample_idtech = (
    "// ................................ Basic ................................ //\n"
    "\r\n"
    "// sv_hostname - Name of the server.\r\n"
    "set sv_hostname \"SERVERNAME\"\r\n"
    "seta rconpassword \"ADMINPASSWORD\"\r\n"
    "sets _Admin \"Admin\"\r\n"
    "; set sv_master2 \"master.example.net:27950\"\r\n"
    "set g_gametype 0\r\n")
sample_properties = (
    "#Minecraft server properties\n"
    "#Thu Mar 26 00:00:00 MDT 2020\n"
    "allow-flight=false\n"
    "difficulty=easy\n"
    "enable-rcon=false\n"
    "level-seed=\n"
    "max-players=20\n"
    "motd=A Minecraft Server\n"
    "rcon.password=ADMINPASSWORD\n"
    "rcon.port=25575\n"
    "resource-pack=https\\://example.invalid/pack.zip\n"
    "long=one \\\n"
    "  two\n"
    "white-list=False\n")
sample_ini = (
    "# Players can hurt and kill other players\r\n"
    "PVP=true\r\n"
    "\r\n"
    "# Toggles global chat on or off.\r\n"
    "GlobalChat=TRUE\r\n"
    "Mods=ModA;ModB\r\n"
    "\r\n"
    "[ServerSettings]\r\n"
    "ServerPassword = hunter2   \r\n"
    "MaxPlayers=32\r\n"
    "!ClearArray=x\r\n")
sample_xml = (
    "<?xml version=\"1.0\"?>\n"
    "<ServerSettings>\n"
    "  <!-- GENERAL SERVER SETTINGS -->\n"
    "\n"
    "  <!-- Server representation -->\n"
    "  <property name=\"ServerName\" value=\"My Game Host\" />   <!-- Whatever you want the name of the server\n"
    "  to be. -->\n"
    "  <property name=\"ServerPassword\" value=\"\" />   <!-- Password to gain entry to the server -->\n"
    "\n"
    "  <!-- Networking -->\n"
    "  <property name=\"ServerPort\" value=\"26900\"/>\n"
    "  <property name='Region' value='NorthAmericaEast' />\n"
    "  <property name=\"Motd\" value=\"Fish &amp; Chips &lt;3\" />\n"
    "  <!-- <property name=\"UserDataFolder\" value=\"absolute path\" /> -->   <!-- Use this to override -->\n"
    "  <property name=\"Weird\" value=\"&custom;\" />\n"
    "  <property name=\"EACEnabled\" value=\"true\" />\n"
    "</ServerSettings>\n")
sample_json = (
    "{\n"
    "  \"name\": \"Name of the game\",\n"
    "  \"tags\": [\"game\", \"tags\"],\n"
    "\n"
    "  \"_comment_max_players\": \"Maximum number of players allowed.\",\n"
    "  \"max_players\": 0,\n"
    "\n"
    "  \"_comment_visibility\": [\"public: published\",\n"
    "                          \"lan: broadcast on LAN\"],\n"
    "  \"visibility\":\n"
    "  {\n"
    "    \"public\": true,\n"
    "    \"lan\": false\n"
    "  },\n"
    "  \"game_password\": \"\",\n"
    "  \"ratio\" : 1.5,\n"
    "  \"motd\": \"caf\\u00e9 \\\"quoted\\\"\",\n"
    "  \"Password\": null,\n"
    "  \"deep\": {\"inner\": {\"x\": 1}}\n"
    "}\n")


def _fields176(rel, content):
    """{key: field} of the form build() draws (the last field of a key wins)."""
    form = _g176.build(rel, content)
    return {} if form is None else {f["key"]: f for g in form["groups"] for f in g["fields"]}


def _apply176(rel, content, changes_by_key):
    """apply() with changes named by key, through the ids build() gave."""
    fields = _fields176(rel, content)
    changes = {str(fields[k]["id"]): v for k, v in changes_by_key.items()}
    return _g176.apply(rel, content, _g176.content_hash(content), changes)


# ── 1. which files get a form ───────────────────────────────────────────────────────────────────
eq("game config form: each format is found by extension, and .cfg/.txt by what most lines look like",
   [_g176.detect(rel, text) for rel, text in (
       ("serverfiles/csgo/cfg/server.cfg", sample_source), ("main/server.cfg", sample_idtech),
       ("serverfiles/server.properties", sample_properties), ("Zomboid/Server/pz.ini", sample_ini),
       ("serverfiles/sdtd.xml", sample_xml), ("data/server-settings.json", sample_json),
       ("serverfiles/valheim.cfg", "name=x\nport=2456\n# c\n"), ("a/b.txt", "MaxPlayers 10\n"),
       ("a/readme.txt", "Hello, world.\nThis is prose, really.\n"), ("a/start.sh", "x=1\n"),
       ("a/noext", "x=1\n"), ("a/server.cfg", "a\x00=1\n"), ("a/x.cfg", ""))],
   ["cfg", "cfg", "kv", "kv", "xml", "json", "kv", "cfg", None, None, None, None, None])
eq("game config form: a DOCTYPE or ENTITY declaration in the XML, JSON that is not an object or not "
   "strict JSON, and a file with no field get no form (raw editor only)",
   [_g176.build(rel, text) for rel, text in (
       ("a.xml", "<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]>\n<property name=\"a\" value=\"&e;\"/>"),
       ("a.xml", "<x><!ENTITY e \"y\"><property name=\"a\" value=\"1\"/></x>"),
       ("a.json", "[1, 2]"), ("a.json", "{\"a\": NaN}"), ("a.json", "{\"a\": 1,}"), ("a.json", "{\"a\": 1} x"),
       ("a.json", "{\"a\": [1]}"), ("a.ini", "# only a comment\n"), ("a.xml", "<x/>"))],
   [None] * 9)

# ── 2. round trips ──────────────────────────────────────────────────────────────────────────────
_samples176 = (("serverfiles/csgo/cfg/server.cfg", sample_source), ("main/server.cfg", sample_idtech),
               ("serverfiles/server.properties", sample_properties), ("Zomboid/Server/pz.ini", sample_ini),
               ("serverfiles/sdtd.xml", sample_xml), ("data/server-settings.json", sample_json))
_same176 = []
for _rel176, _text176 in _samples176:
    _f176 = _fields176(_rel176, _text176)
    _same176.append(_g176.apply(_rel176, _text176, _g176.content_hash(_text176),
                                {str(f["id"]): f["value"] for f in _f176.values()}) == (_text176, [], None))
eq("game config form: every sample saved with nothing changed is the same text (and no change is reported)",
   _same176, [True] * 6)

eq("game config form: Source cfg - only the changed values differ; an unquoted value given a blank is quoted",
   _apply176("server.cfg", sample_source, {"hostname": "My Server", "sv_lan": "1", "sv_region": "3",
                                           "exec": "my bans.cfg", "rcon_password": "s3cret"})[0],
   sample_source.replace("\"SERVERNAME\"", "\"My Server\"").replace("\nsv_lan 0\n", "\nsv_lan 1\n")
   .replace("sv_region -1   //", "sv_region 3   //").replace("exec banned_user.cfg", "exec \"my bans.cfg\"")
   .replace("\"ADMINPASSWORD\"", "\"s3cret\""))
eq("game config form: idTech cfg - set/seta/sets lines keep their prefix, CRLF endings stay CRLF",
   _apply176("server.cfg", sample_idtech, {"sv_hostname": "Q", "rconpassword": "", "g_gametype": "4"})[0],
   sample_idtech.replace("\"SERVERNAME\"", "\"Q\"").replace("\"ADMINPASSWORD\"", "\"\"")
   .replace("g_gametype 0", "g_gametype 4"))
eq("game config form: server.properties - an empty value filled, a switch flipped in its own spelling, "
   "everything else byte-identical",
   _apply176("server.properties", sample_properties, {"level-seed": "12345", "white-list": "True",
                                                      "max-players": "8", "motd": "Hi = there # 1"})[0],
   sample_properties.replace("level-seed=\n", "level-seed=12345\n").replace("white-list=False", "white-list=True")
   .replace("max-players=20", "max-players=8").replace("motd=A Minecraft Server", "motd=Hi = there # 1"))
eq("game config form: .ini - spaces around = and after the value kept, CRLF kept, sections kept",
   _apply176("pz.ini", sample_ini, {"ServerPassword": "pa55", "GlobalChat": "FALSE", "Mods": "ModC"})[0],
   sample_ini.replace("ServerPassword = hunter2   ", "ServerPassword = pa55   ")
   .replace("GlobalChat=TRUE", "GlobalChat=FALSE").replace("Mods=ModA;ModB", "Mods=ModC"))
eq("game config form: XML - only the value attribute's text changes, escaped for its own quote",
   _apply176("sdtd.xml", sample_xml, {"ServerName": "A & B <\"x\">", "Region": "Europe's", "ServerPort": "26901",
                                      "EACEnabled": "false"})[0],
   sample_xml.replace("value=\"My Game Host\"", "value=\"A &amp; B &lt;&quot;x&quot;&gt;\"")
   .replace("value='NorthAmericaEast'", "value='Europe&apos;s'").replace("\"26900\"", "\"26901\"")
   .replace("value=\"true\"", "value=\"false\""))
eq("game config form: JSON - strings re-encoded, numbers and switches written bare, a null filled as a "
   "string, the file's own layout kept",
   _apply176("s.json", sample_json, {"name": "no: é \"q\"", "max_players": "16",
                                     "lan": "true", "ratio": "2.5e1", "Password": "pw"})[0],
   sample_json.replace("\"Name of the game\"", "\"no: é \\\"q\\\"\"").replace("\": 0,", "\": 16,")
   .replace("\"lan\": false", "\"lan\": true").replace("\"ratio\" : 1.5", "\"ratio\" : 2.5e1")
   .replace("\"Password\": null", "\"Password\": \"pw\""))
_jnew176 = _apply176("s.json", sample_json, {"motd": "new \"m\""})[0]
check("game config form: JSON - the written file is still JSON and reads the new value",
      _json176.loads(_jnew176)["motd"] == "new \"m\"" and _json176.loads(_jnew176)["deep"] == {"inner": {"x": 1}},
      repr(_jnew176))

# ── 3. what a field is ──────────────────────────────────────────────────────────────────────────
_src176 = _fields176("server.cfg", sample_source)
eq("game config form: Source cfg - groups from the // .... Title .... // lines, the comment above as help, "
   "a trailing // comment not in the value, a bare command no field",
   ([g["name"] for g in _g176.build("server.cfg", sample_source)["groups"]], _src176["hostname"]["help"],
    _src176["sv_lan"]["help"], _src176["sv_region"]["value"], "writeid" in _src176, _src176["sv_tags"]["value"]),
   (["Basic", "Security"], "hostname - Name of the server.", "LAN mode - can't connect from the internet.\n"
    "Default: sv_lan 0", "-1", False, ""))
eq("game config form: 0/1 is a switch only when its help says which is off and which on; else a number",
   [(_src176[k]["kind"], _src176[k]["on"], _src176[k]["off"]) for k in ("logfile", "sv_lan", "sv_region")],
   [("bool", "1", "0"), ("number", None, None), ("number", None, None)])
_props176 = _fields176("server.properties", sample_properties)
eq("game config form: .properties - switches keep their case, a continued line is no field, \\: shown as "
   "written, and the line after a continuation is not read as a key",
   ([(_props176[k]["kind"], _props176[k]["on"], _props176[k]["off"]) for k in ("allow-flight", "white-list")],
    "long" in _props176, any(k.strip().startswith("two") for k in _props176),
    _props176["resource-pack"]["value"], _props176["max-players"]["kind"], _props176["level-seed"]["kind"]),
   ([("bool", "true", "false"), ("bool", "True", "False")], False, False,
    "https\\://example.invalid/pack.zip", "number", "text"))
_ini176 = _fields176("pz.ini", sample_ini)
eq("game config form: .ini - [sections] group the keys, # comments are help, a leading ! is a key "
   "(Unreal's operator), never a comment",
   ([g["name"] for g in _g176.build("pz.ini", sample_ini)["groups"]], _ini176["PVP"]["help"],
    _ini176["GlobalChat"]["on"], _ini176["ServerPassword"]["value"], "!ClearArray" in _ini176),
   (["", "ServerSettings"], "Players can hurt and kill other players", "TRUE", "hunter2", True))
_xml176 = _fields176("sdtd.xml", sample_xml)
eq("game config form: XML - own-line comments name the groups, the comment beside a property is its help, "
   "entities decoded, a property inside a comment or with an unknown entity is no field",
   ([g["name"] for g in _g176.build("sdtd.xml", sample_xml)["groups"]], _xml176["ServerName"]["help"],
    _xml176["Motd"]["value"], "UserDataFolder" in _xml176, "Weird" in _xml176, _xml176["Region"]["value"],
    _xml176["ServerPort"]["help"]),
   (["Server representation", "Networking"], "Whatever you want the name of the server to be.",
    "Fish & Chips <3", False, False, "NorthAmericaEast", "Networking"))
_js176 = _fields176("s.json", sample_json)
eq("game config form: JSON - one level of nesting is a group, deeper nesting and lists are no fields, "
   "_comment_<key> is that key's help, null shows empty",
   ([g["name"] for g in _g176.build("s.json", sample_json)["groups"]], sorted(_js176),
    _js176["max_players"]["help"], _js176["visibility" if "visibility" in _js176 else "public"]["help"],
    _js176["motd"]["value"], _js176["Password"]["value"], _js176["lan"]["kind"], _js176["ratio"]["kind"]),
   (["", "visibility"], ["Password", "game_password", "lan", "max_players", "motd", "name", "public", "ratio"],
    "Maximum number of players allowed.", "", "café \"quoted\"", "", "bool", "number"))

eq("game config form: the secret rule - a password/secret/token/apikey anywhere, or the WORD key, pass, "
   "pwd or rcon; not when another word says port, address or a switch",
   [_g176.is_secret_key(k) for k in (
       "rcon_password", "rconpassword", "ServerPassword", "sv_password", "g_password", "sv_privatePassword",
       "wsapikey", "DiscordToken", "auth_token", "client_secret", "AdminKey", "steam-key", "sv_pass", "rcon",
       "RCON", "TelnetPwd", "Passwd",
       "rcon.port", "broadcast-rcon-to-ops", "RCONEnabled", "rcon_ip", "keyboard_layout", "monkey_mode",
       "passive_mobs", "hostname", "max-players", "KeyCount", "", None)],
   [True] * 17 + [False] * 9 + [True, False, False])
eq("game config form: a switch is never masked, a secret-named text or number field is",
   [(_props176["enable-rcon"]["secret"], _props176["rcon.password"]["secret"], _props176["rcon.port"]["secret"]),
    (_src176["rcon_password"]["secret"], _xml176["ServerPassword"]["secret"],
     _fields176("a.cfg", "sv_password 1234\n")["sv_password"]["secret"])],
   [(False, True, False), (True, True, True)])

# ── 4. refusals ─────────────────────────────────────────────────────────────────────────────────
_hash176 = _g176.content_hash(sample_source)
eq("game config form: a save naming another text's hash is refused as changed since it was opened",
   [_g176.apply("server.cfg", sample_source, h, {"0": "x"})[2] for h in (
       _g176.content_hash(sample_source + " "), "", None, 5)],
   [_g176.CHANGED] * 4)
eq("game config form: a field id that is not in the file, or a change map that is not a map, is refused",
   [_g176.apply("server.cfg", sample_source, _hash176, c)[2] for c in (
       {"99": "x"}, {"-1": "x"}, {"01": "x"}, {"a": "x"}, {True: "x"}, ["x"], "x", {"0": 5}, {"0": None})],
   [_g176.NO_FIELD] * 5 + [_g176.BAD_CHANGES] * 4)
eq("game config form: a value with a line break, a control character or a Unicode line separator is "
   "refused in every format",
   [_apply176(rel, text, {key: bad})[2] for rel, text, key in (
       ("server.cfg", sample_source, "hostname"), ("s.properties", sample_properties, "motd"),
       ("s.xml", sample_xml, "ServerName"), ("s.json", sample_json, "name"))
    for bad in ("a\nb", "a\rb", "a\x00b", "a\x1bb", "a b", "a\x85b")],
   [_g176.BAD_CHARS] * 24)
eq("game config form: a value over 4096 characters is refused",
   _apply176("server.cfg", sample_source, {"hostname": "x" * 4097})[2], _g176.TOO_LONG)
_refusals176 = [str(_apply176(rel, text, ch)[2]) for rel, text, ch in (
    ("server.cfg", sample_source, {"hostname": "a\"b"}),
    ("server.cfg", sample_source, {"exec": "a;quit"}),
    ("server.cfg", sample_source, {"exec": "a//b"}),
    ("s.properties", sample_properties, {"motd": " lead"}),
    ("s.properties", sample_properties, {"motd": "trail "}),
    ("s.properties", sample_properties, {"motd": "ends\\"}),
    ("s.properties", sample_properties, {"allow-flight": "yes"}),
    ("s.properties", sample_properties, {"max-players": "lots"}),
    ("s.json", sample_json, {"max_players": "1e"}),
    ("s.json", sample_json, {"lan": "False"}))]
eq("game config form: a quote in a cfg value, ; or // in an unquoted one, a space at either end of a "
   "key=value value, a trailing backslash in .properties, a third value for a switch, text in a number field",
   _refusals176,
   ["hostname: a value in this file cannot hold a double quote (\").",
    "exec: an unquoted value in this file cannot hold ; or // (they end the value).",
    "exec: an unquoted value in this file cannot hold ; or // (they end the value).",
    "motd: this file does not keep a space at the start or end of a value.",
    "motd: this file does not keep a space at the start or end of a value.",
    "motd: a value cannot end with a backslash in this file (it would join the next line).",
    "allow-flight is a switch: it takes true or false.",
    "max-players takes a number.", "max_players takes a number.", "lan is a switch: it takes true or false."])
eq("game config form: ; and // are fine inside a quoted cfg value, and an ini value may end in a backslash",
   [_apply176("server.cfg", sample_source, {"hostname": "a;b//c"})[2],
    _apply176("pz.ini", sample_ini, {"Mods": "\\ModB42\\"})[2]], [None, None])
_enc176 = _g176._gcf_encode
try:
    # An encoder that let a line break through: the read-back sees a field more and refuses.
    _g176._gcf_encode = lambda fmt, f, value: value + "\nextra=1"
    _unsafe176 = _g176.apply("x.ini", "a=1\nb=2\n", _g176.content_hash("a=1\nb=2\n"), {"0": "5"})
finally:
    _g176._gcf_encode = _enc176
eq("game config form: a change that would read back as other fields is refused, never written",
   _unsafe176, (None, [], _g176.UNSAFE))
_ver176 = _g176._gcf_same_fields
eq("game config form: the read-back check compares every field - a changed key, section or an untouched "
   "value that moved fails it",
   [_ver176([{"key": "a", "section": "", "value": "1"}], [{"key": "a", "section": "", "value": "1"}], {}),
    _ver176([{"key": "a", "section": "", "value": "1"}], [{"key": "b", "section": "", "value": "1"}], {}),
    _ver176([{"key": "a", "section": "", "value": "1"}], [{"key": "a", "section": "s", "value": "1"}], {}),
    _ver176([{"key": "a", "section": "", "value": "1"}], [{"key": "a", "section": "", "value": "2"}], {}),
    _ver176([{"key": "a", "section": "", "value": "1"}], [{"key": "a", "section": "", "value": "2"}], {0: "2"}),
    _ver176([{"key": "a", "section": "", "value": "1"}], [], {})],
   [True, False, False, False, True, False])
eq("game config form: the audit text names each changed key with its values, a secret only as changed",
   _g176.audit_detail([({"key": "hostname", "secret": False}, "old", "new"),
                       ({"key": "rcon_password", "secret": True}, "ADMINPASSWORD", "s3cret"),
                       ({"key": "motd", "secret": False}, "x" * 70, "y")]),
   "hostname: old -> new; rcon_password: changed (hidden); motd: " + "x" * 59 + "… -> y")

# ── 5. details naming the file ──────────────────────────────────────────────────────────────────
eq("game config: details naming a server.properties, .ini, .xml or .json config is found, not only a .cfg; "
   "a backup name or a directory is not",
   [_files176._r21b_reported_config_rel("  Config file:\t/home/u/%s\n" % p, "u") for p in (
       "serverfiles/server.properties", "Zomboid/Server/u.ini", "serverfiles/sdtd.xml", "serverfiles/data/s.json",
       "serverfiles/cfg/server.cfg", "serverfiles/cfg/server.cfg.bak", "serverfiles/Saves")]
   + [_files176._r21b_reported_config_rel("Config file:\t/home/u/serverfiles/server.properties (FILE MISSING)\n",
                                          "u")],
   ["serverfiles/server.properties", "Zomboid/Server/u.ini", "serverfiles/sdtd.xml", "serverfiles/data/s.json",
    "serverfiles/cfg/server.cfg", None, None, "serverfiles/server.properties"])

# ── 6. the routes ───────────────────────────────────────────────────────────────────────────────
_sid176 = _p9_new_server(P9_HOST, "p176mc", "mc", 25565, name="p176-mc", status="online")
_rel176 = "serverfiles/server.properties"
_files_on176 = {_rel176: sample_properties}
_writes176, _refused176 = [], []
_wrefuse176 = {"on": False}
_rrefuse176 = {"on": False}
_write_ok176 = {"v": (True, "")}


def _read176(server, user, relpath, max_bytes=1048576):
    return (_files_on176[relpath], None) if relpath in _files_on176 else (None, "File not found")


def _write176(server, user, relpath, content, selfname=None):
    _writes176.append((user, relpath, content, selfname))
    return _write_ok176["v"]


def _refuser176(flag, kind):
    def _r(gs, action, detail=""):
        if not flag["on"]:
            return None
        _refused176.append((kind, action, detail))
        from flask import jsonify
        return jsonify({"success": False, "message": "refused", "error": "refused"}), 409
    return _r


def _j176(r):
    return r.get_json(silent=True) or {}


_r176 = {}
_u176 = "/api/server/%d/game-config/form" % _sid176
_fid176 = {k: str(f["id"]) for k, f in _fields176(_rel176, sample_properties).items()}
_h176 = _g176.content_hash(sample_properties)
try:
    _p9_arm(who="part176")
    _p9_patch_sm("read_file", _read176)
    _p9_patch_sm("write_file", _write176)
    _p9_patch_sm("lgsm_game_config", lambda s, u, n: {"rel": _rel176, "content": sample_properties,
                                                           "exists": True, "error": None})
    _p9_patch(_sf176, "_write_refused", _refuser176(_wrefuse176, "write"))
    _p9_patch(_sf176, "_read_refused", _refuser176(_rrefuse176, "read"))
    _A176, _V176 = _p9_client(P9_ADMIN), _p9_client(P9_VIEWER)

    _r176["read"] = _A176.get("/api/server/%d/game-config" % _sid176)
    _p9_patch_sm("lgsm_game_config", lambda s, u, n: {"rel": "a/start.sh", "content": "x=1\n",
                                                           "exists": True, "error": None})
    _r176["read_other"] = _A176.get("/api/server/%d/game-config" % _sid176)
    _p9_patch_sm("lgsm_game_config", lambda s, u, n: {"rel": None, "content": "", "exists": False,
                                                           "error": "No editable game config file"})
    _r176["read_none"] = _A176.get("/api/server/%d/game-config" % _sid176)

    _r176["save"] = _A176.post(_u176, json={"path": _rel176, "hash": _h176, "changes": {
        _fid176["motd"]: "Hello", _fid176["rcon.password"]: "n3w-secret", _fid176["white-list"]: "True",
        _fid176["difficulty"]: "easy"}})
    _r176["save_writes"] = list(_writes176)
    _r176["save_audit"] = _p9_audit("edit_file")
    _n176 = (len(_writes176), _p9_audit_count("edit_file"))
    _r176["stale"] = _A176.post(_u176, json={"path": _rel176, "hash": _g176.content_hash("other"),
                                             "changes": {_fid176["motd"]: "x"}})
    _r176["stale_audit"] = _p9_audit("edit_file")
    _r176["bad"] = [_A176.post(_u176, json=b).status_code for b in (
        {"path": _rel176, "hash": _h176, "changes": {_fid176["motd"]: "a\nrcon.password=x"}},
        {"path": _rel176, "hash": _h176, "changes": {_fid176["max-players"]: "many"}},
        {"path": _rel176, "hash": _h176, "changes": {"999": "x"}},
        {"path": _rel176, "hash": _h176, "changes": "motd=x"},
        {"path": 5, "hash": _h176, "changes": {}}, {"hash": _h176, "changes": {}}, [1, 2])]
    _r176["missing"] = _A176.post(_u176, json={"path": "serverfiles/nope.properties", "hash": _h176,
                                               "changes": {"0": "x"}})
    _r176["after_bad"] = (len(_writes176) - _n176[0], _p9_audit_count("edit_file") - _n176[1])
    _r176["nothing"] = _A176.post(_u176, json={"path": _rel176, "hash": _h176, "changes": {
        _fid176["motd"]: "A Minecraft Server"}})
    _r176["nothing_writes"] = len(_writes176) - _n176[0]
    _r176["viewer"] = _V176.post(_u176, json={"path": _rel176, "hash": _h176, "changes": {_fid176["motd"]: "v"}})
    _r176["viewer_get"] = _V176.get(_u176 + "?path=" + _rel176)
    _write_ok176["v"] = (False, "bash: host text")
    _r176["failed"] = _A176.post(_u176, json={"path": _rel176, "hash": _h176, "changes": {_fid176["motd"]: "F"}})
    _r176["failed_audit"] = _p9_audit("edit_file")
    _write_ok176["v"] = (True, "")
    _wrefuse176["on"] = True
    _n176 = len(_writes176)
    _r176["refused"] = _A176.post(_u176, json={"path": _rel176, "hash": _h176, "changes": {_fid176["motd"]: "R"}})
    _r176["refused_writes"] = len(_writes176) - _n176
    _wrefuse176["on"] = False
    _r176["get"] = _A176.get(_u176 + "?path=" + _rel176)
    _r176["get_missing"] = _A176.get(_u176 + "?path=serverfiles/nope.properties")
    _rrefuse176["on"] = True
    _r176["get_refused"] = _A176.get(_u176 + "?path=" + _rel176)
    _rrefuse176["on"] = False
    _r176["refusals"] = list(_refused176)
finally:
    _p9_restore_all()
    _p9_delete_server(_sid176)

_jr176 = _j176(_r176["read"])
check("game config read: the answer carries the form for a format it reads, with the hash of the text read",
      isinstance(_jr176.get("form"), dict) and _jr176["form"]["format"] == "kv"
      and _jr176["form"]["hash"] == _h176 and _jr176.get("content") == sample_properties, repr(_jr176)[:300])
check("game config read: ...and no form for a file it does not read, or when no file was found",
      _j176(_r176["read_other"]).get("form") is None and _j176(_r176["read_other"]).get("rel") == "a/start.sh"
      and _j176(_r176["read_none"]).get("form") is None
      and "No editable" in (_j176(_r176["read_none"]).get("error") or ""),
      repr([_j176(_r176["read_other"]), _j176(_r176["read_none"])])[:300])
_want176 = (sample_properties.replace("motd=A Minecraft Server", "motd=Hello")
            .replace("rcon.password=ADMINPASSWORD", "rcon.password=n3w-secret").replace("white-list=False",
                                                                                        "white-list=True"))
check("game config form save: only the changed values are written, through the file editor's writer as the "
      "game account, and the answer carries the new text and its form",
      _r176["save_writes"] == [("p176mc", _rel176, _want176, _r176["save_writes"][0][3])]
      and _j176(_r176["save"]).get("success") is True and _j176(_r176["save"]).get("content") == _want176
      and _j176(_r176["save"])["form"]["hash"] == _g176.content_hash(_want176), repr(_r176["save_writes"])[:400])
check("game config form save: the audit row names the changed keys and values, against the server, and the "
      "secret's old and new values are not in it",
      _r176["save_audit"].success is True and _r176["save_audit"].target == "p176-mc"
      and _r176["save_audit"].detail == (_rel176 + " (form): motd: A Minecraft Server -> Hello; "
                                         "rcon.password: changed (hidden); white-list: False -> True")
      and "ADMINPASSWORD" not in _r176["save_audit"].detail and "n3w" not in _r176["save_audit"].detail,
      repr(_r176["save_audit"]))
check("game config form save: a file changed since the form was built is a 409 saying so, audited as refused",
      _r176["stale"].status_code == 409 and _j176(_r176["stale"]).get("message") == _g176.CHANGED
      and _r176["stale_audit"].success is False and _g176.CHANGED in _r176["stale_audit"].detail,
      repr((_r176["stale"].status_code, _j176(_r176["stale"]), _r176["stale_audit"])))
check("game config form save: a line break, text for a number, an unknown field, a non-map, a bad or missing "
      "path, a non-object body and a missing file are refused and write nothing",
      _r176["bad"] == [400, 400, 400, 400, 400, 400, 400] and _r176["missing"].status_code == 409
      and _r176["after_bad"][0] == 0, repr((_r176["bad"], _r176["missing"].status_code, _r176["after_bad"])))
check("game config form save: values equal to the file's are no change: nothing is written",
      _j176(_r176["nothing"]).get("success") is True and _r176["nothing_writes"] == 0
      and _j176(_r176["nothing"]).get("message") == "Nothing changed.", repr(_j176(_r176["nothing"])))
check("game config form: a console viewer is refused reading or saving (the Settings tab's permission)",
      _r176["viewer"].status_code == 403 and _r176["viewer_get"].status_code == 403,
      repr((_r176["viewer"].status_code, _r176["viewer_get"].status_code)))
check("game config form save: a failed write says the panel's reason, never the host's output, and is audited "
      "as failed",
      _j176(_r176["failed"]).get("success") is False and "bash" not in _j176(_r176["failed"]).get("message", "")
      and _r176["failed_audit"].success is False and "bash" not in _r176["failed_audit"].detail,
      repr((_j176(_r176["failed"]), _r176["failed_audit"])))
check("game config form: the file browser's refusals are asked - a refused write writes nothing, a refused "
      "read reads nothing - with the path",
      _r176["refused"].status_code == 409 and _r176["refused_writes"] == 0
      and _r176["get_refused"].status_code == 409
      and ("write", "edit_file", _rel176) in _r176["refusals"]
      and ("read", "read_file", _rel176) in _r176["refusals"],
      repr(_r176["refusals"]))
check("game config form: the re-read answers the file and its form; a missing file is an error, not a form",
      _j176(_r176["get"]).get("content") == sample_properties and _j176(_r176["get"])["form"]["hash"] == _h176
      and _r176["get_missing"].status_code == 400 and "form" not in _j176(_r176["get_missing"]),
      repr((_j176(_r176["get"]).get("form", {}).get("hash"), _r176["get_missing"].status_code)))
check("game config form: form_for builds nothing for a read that found no file",
      [_gr176.form_for(x) for x in (None, {}, {"rel": "a.ini", "content": "a=1", "exists": False},
                                    {"rel": None, "content": "a=1", "exists": True})] == [None] * 4)

# ── 7. the page script in node ──────────────────────────────────────────────────────────────────
with open(_os176.path.join(_root, "panel", "static", "js", "server_files.js"), encoding="utf-8") as _fh176:
    _page176 = _fh176.read()
_cut176 = _page176[_page176.index("var _gcfForm=null"):_page176.index("// After the raw editor saved")]
_dom176 = r"""
global.window = global; const els = {};
function mk(tag){ const e = {tagName: tag, attrs: {}, children: [], dataset: {}, style: {}, value: '',
  checked: false, classList: {list: [], add(...c){ this.list.push(...c); }, toggle(){}},
  setAttribute(k, v){ this.attrs[k] = String(v); },
  appendChild(c){ this.children.push(c); if (c.id) els[c.id] = c; },
  replaceChildren(...c){ this.children = c; }};
  return e; }
global.document = {createElement: mk, getElementById: (id) => els[id] || (els[id] = mk('div'))};
global._icon = (c) => mk('i');
var gameCfgRel = 'serverfiles/server.properties', MOUNT = '', serverId = 1, posted = null;
global.fetch = (u, o) => { posted = JSON.parse(o.body); return {then: () => ({then: () => ({catch: () => 0})})}; };
"""
_prog176 = _dom176 + _cut176 + r"""
const form = {format: 'kv', hash: 'H', groups: [{name: '', fields: [
  {id: 0, key: 'rcon.password', value: 'ADMINPASSWORD', kind: 'text', help: 'h', secret: true, on: null, off: null},
  {id: 1, key: 'white-list', value: 'False', kind: 'bool', help: '', secret: false, on: 'True', off: 'False'},
  {id: 2, key: 'max-players', value: '20', kind: 'number', help: '', secret: false, on: null, off: null}]}]};
document.getElementById('game-cfg').value = 'TEXT'; _gcfShown = 'TEXT';
_gcfSet(form);
const pw = els['gcf-f-0'];
const attrs = JSON.stringify(Object.values(els).map(e => [e.attrs, e.dataset, e.id || '']));
const before = _gcfChanges();
els['gcf-f-1'].checked = true; els['gcf-f-2'].value = '8';
saveGameForm();
console.log(JSON.stringify({type: pw.type, value: pw.value, inAttrs: attrs.indexOf('ADMINPASSWORD') >= 0,
  before: before, posted: posted, view: els['gcf-form-pane'].style.display}));
"""
_out176 = _run_js75("game config form page: a secret only in the input's value property, only changes sent",
                    _prog176)
if _out176 is not None:
    check("game config form page: a secret field is a password input holding its value as a property, and the "
          "value is in no attribute or data- field",
          _out176.get("type") == "password" and _out176.get("value") == "ADMINPASSWORD"
          and _out176.get("inAttrs") is False, repr(_out176))
    check("game config form page: nothing is sent before a change; then only the changed fields, a switch in "
          "the file's own spelling, with the hash and path the form came with",
          _out176.get("before") is None and _out176.get("posted") == {
              "path": "serverfiles/server.properties", "hash": "H", "changes": {"1": "True", "2": "8"}}
          and _out176.get("view") == "", repr(_out176))
