"""A form view of a game's own config file: its fields read out, and changed values written back.

Pure functions: no request handling, no host access. The route (panel/routes/game_config_form.py) reads and
writes the file through the file editor's helpers; this module only turns text into fields and
fields back into text.

FORMATS, chosen by the file's extension and then by what its lines look like:

* ``kv`` - ``key=value`` lines: ``.properties`` (Minecraft's server.properties), ``.ini`` with
  ``[sections]`` (Project Zomboid, Unreal engine games), and ``.cfg``/``.txt``/``.conf`` files whose
  lines are mostly ``key=value``. Comments start with ``#`` or ``;`` (``!`` too in ``.properties``,
  never in ``.ini``, where Unreal uses a leading ``!`` as an operator).
* ``cfg`` - Source and idTech console scripts: ``key "value"`` or ``key value``, ``//`` comments,
  and idTech3's ``set``/``seta``/``sets``/``setu``/``setb key "value"``. A ``// .... Title .... //``
  line names the group the keys after it belong to.
* ``xml`` - 7 Days to Die's ``<property name="X" value="Y"/>``. Read with regular expressions, never
  an XML parser: a file holding a DOCTYPE or an ENTITY declaration gets no form at all, so nothing is
  ever expanded or fetched.
* ``json`` - an object of scalars, with objects of scalars one level down shown as groups. Factorio's
  ``_comment_<key>`` members are that key's help, not fields.

THE GUARANTEE. Every field remembers where its value's text sits in the file. A save splices the new
text into exactly those places and nothing else, so comments, order, blank lines, line endings,
spacing and every other value's quoting stay byte for byte as they were. The result is parsed again
before it is handed back: the same fields must come out, the changed ones holding their new values
and the rest their old text, or the save is refused. Values are edited; keys are never added or
removed here (the raw editor does that).

A save names the hash of the text the form was built from; when the file now hashes differently the
save is refused, because the positions it would write to belong to another text.
"""
import hashlib
import html
import json
import re
import unicodedata

from panel.core import i18n

# A file with more fields than this is offered in the raw editor only.
MAX_FIELDS = 2000
VALUE_MAX = 4096
_GCF_HELP_MAX = 600
_GCF_SECTION_MAX = 80

CHANGED = "The file changed since you opened it. Reload it and make your changes again."
NO_FORM = "This file has no form view. Use the raw editor."
BAD_CHANGES = "The changes must be a map of field numbers to text values."
NO_FIELD = "A changed field is not in this file. Reload it and try again."
BAD_CHARS = "A value cannot hold a line break or a control character."
TOO_LONG = "A value can be at most 4096 characters."
BAD_BOOL = "{key} is a switch: it takes {on} or {off}."
BAD_NUMBER = "{key} takes a number."
EDGE_SPACE = "{key}: this file does not keep a space at the start or end of a value."
TRAIL_BACKSLASH = "{key}: a value cannot end with a backslash in this file (it would join the next line)."
CFG_QUOTE = "{key}: a value in this file cannot hold a double quote (\")."
CFG_BREAKS = "{key}: an unquoted value in this file cannot hold ; or // (they end the value)."
UNSAFE = "This change could not be written safely. Use the raw editor."

_GCF_EXT_FORMATS = {".properties": ("kv",), ".ini": ("kv",), ".xml": ("xml",), ".json": ("json",),
                    ".cfg": ("cfg", "kv"), ".txt": ("cfg", "kv"), ".conf": ("cfg", "kv")}
_GCF_EOL = re.compile(r"\r\n|\r|\n")
_GCF_NUMBER = re.compile(r"-?\d+(?:\.\d+)?")
_GCF_JSON_NUMBER = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?")
_GCF_BOOL_WORDS = {"true": "false", "false": "true"}
# A 0/1 value is a switch only when its help says which is off and which is on ("0 = off, 1 = on",
# "logfile - 0 = disabled, 1 = enabled", "(0/1)"). Without that, 0 and 1 are numbers: a player limit
# of 1 is not a switch.
_GCF_OFF = r"(?:off|disabled?|no|false)"
_GCF_ON = r"(?:on|enabled?|yes|true)"
_GCF_TOGGLE_HELP = re.compile(
    r"\b0\s*[=:-]?\s*%s\b.*\b1\s*[=:-]?\s*%s\b|\b1\s*[=:-]?\s*%s\b.*\b0\s*[=:-]?\s*%s\b|\(\s*[01]\s*/\s*[01]\s*\)"
    % (_GCF_OFF, _GCF_ON, _GCF_ON, _GCF_OFF), re.I | re.S)

# ── secret keys ──────────────────────────────────────────────────────────────────────────────────
# A key is secret when, lower-cased with its separators removed, it CONTAINS one of the substrings
# (rcon_password, rconpassword, ServerPassword, wsapikey, auth_token), or when one of its WORDS
# (split on anything not a letter or digit, and between a lower-case letter and a capital) is one
# of the words: AdminKey, sv_pass, rcon. "key" and "pass" are whole words only, so keyboard_layout,
# passive_mobs and monkey_mode are not secret. A key matched only by a word is still not secret
# when another of its words says it is a port, an address or a switch: rcon.port,
# broadcast-rcon-to-ops and RCONEnabled are not secrets. A switch (true/false) is never masked: its
# value is only on or off.
_GCF_SECRET_SUBSTR = ("password", "passwd", "passphrase", "secret", "token", "apikey", "authkey",
                      "privatekey")
_GCF_SECRET_WORDS = frozenset({"pass", "pwd", "key", "rcon"})
_GCF_NOT_SECRET_WORDS = frozenset({"port", "ip", "address", "enable", "enabled", "broadcast", "timeout",
                                   "log", "logging"})
_GCF_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def is_secret_key(key):
    """True when `key` names a value to show as a password field (see the rule above)."""
    if not isinstance(key, str):
        return False
    flat = re.sub(r"[^a-z0-9]", "", key.lower())
    if any(s in flat for s in _GCF_SECRET_SUBSTR):
        return True
    words = {w.lower() for w in re.split(r"[^A-Za-z0-9]+", _GCF_CAMEL.sub(" ", key)) if w}
    return bool(words & _GCF_SECRET_WORDS) and not words & _GCF_NOT_SECRET_WORDS


def content_hash(content):
    """The hash a save names: sha256 of the text as UTF-8 (a lone surrogate written escaped)."""
    return hashlib.sha256((content or "").encode("utf-8", "surrogatepass")).hexdigest()


# ── reading ──────────────────────────────────────────────────────────────────────────────────────
def _gcf_lines(text):
    """(offset, body) for each line of `text`, the body without its line ending."""
    pos, n = 0, len(text)
    while pos < n:
        m = _GCF_EOL.search(text, pos)
        end = m.start() if m else n
        yield pos, text[pos:end]
        pos = m.end() if m else n


def _gcf_entry(key, start, end, value, section, help_lines, style=""):
    """One field as the parsers record it: where its value's text is, and what it means."""
    help_text = "\n".join(help_lines).strip()
    return {"key": key, "start": start, "end": end, "value": value, "section": section,
            "help": help_text[:_GCF_HELP_MAX], "style": style}


def _gcf_is_decoration(text):
    """True for a comment that is only a rule of punctuation (// ******, # -----)."""
    return not re.search(r"[A-Za-z0-9]", text)


# key=value


class _GcfKV:
    r"""A key=value line taken apart: group(1) the key, group(2) the value, start/end(2) its span.

    String operations, not a regex: the pattern this replaces (`[ \t]*([^\s=#;\[][^=]*?)[ \t]*=[ \t]*
    (.*?)[ \t]*\Z`) backtracked super-linearly on a long line of blanks, and the file is the game
    account's to write. Same answers: the key is what precedes the first `=`, without the blanks
    round it, and may not start with a blank, `=`, `#`, `;` or `[`; the value is the rest, without
    the spaces and tabs round it.
    """

    __slots__ = ("_key", "_value", "_start")

    def __init__(self, key, value, start):
        self._key, self._value, self._start = key, value, start

    def group(self, n):
        return self._key if n == 1 else self._value

    def start(self, _n=2):
        return self._start

    def end(self, _n=2):
        return self._start + len(self._value)


def _gcf_kv_match(body):
    """A _GcfKV for a key=value line, or None."""
    eq = body.find("=")
    if eq < 0:
        return None
    key = body[:eq].lstrip(" \t").rstrip(" \t")
    if not key or key[0].isspace() or key[0] in "=#;[":
        return None
    rest = body[eq + 1:]
    lead = len(rest) - len(rest.lstrip(" \t"))
    return _GcfKV(key, rest[lead:].rstrip(" \t"), eq + 1 + lead)


_GCF_KV_SECTION = re.compile(r"[ \t]*\[([^\]\r\n]+)\][ \t]*\Z")


def _gcf_kv_comment(body, props):
    """The comment's text when `body` is a comment line of a key=value file, else None."""
    m = re.match(r"[ \t]*([#;!]+)(.*)\Z" if props else r"[ \t]*([#;]+)(.*)\Z", body)
    return m.group(2).strip() if m else None


def _gcf_kv_line(body, props):
    """What one line of a key=value file is: (kind, detail) - comment, section, join, entry or other."""
    comment = _gcf_kv_comment(body, props)
    if comment is not None:
        return "comment", comment
    sec = _GCF_KV_SECTION.match(body)
    if sec:
        return "section", sec.group(1).strip()
    m = _gcf_kv_match(body)
    if m and props and _gcf_odd_backslashes(m.group(2)):
        return "join", m   # a value that goes on to the next line: the raw editor's to change
    return ("entry", m) if m else ("other", None)


def _gcf_parse_kv(text, props):
    r"""Fields of a key=value file. `props`: it is a .properties file (! comments, \ line joins)."""
    out, section, pending, joining = [], "", [], False
    for off, body in _gcf_lines(text):
        if joining:   # a .properties value continued from the line above: not a field of its own
            joining = props and _gcf_odd_backslashes(body)
            continue
        kind, got = _gcf_kv_line(body, props)
        if kind == "comment":
            pending += [] if _gcf_is_decoration(got) else [got]
            continue
        if kind == "section":
            section = got
        elif kind == "entry":
            out.append(_gcf_entry(got.group(1), off + got.start(2), off + got.end(2), got.group(2), section, pending))
        joining = kind == "join"
        pending = []
    return out


def _gcf_odd_backslashes(s):
    """True when `s` ends in an odd run of backslashes (a .properties line that continues)."""
    return (len(s) - len(s.rstrip("\\"))) % 2 == 1


# Source / idTech console scripts
_GCF_CFG = re.compile(r'[ \t]*(?:(?:set|seta|sets|setu|setb)[ \t]+)?([A-Za-z_][\w.\-+]*)[ \t]+'
                      r'(?:"([^"]*)"|([^"\s;][^";]*?))[ \t]*(?://.*)?\Z')


def _gcf_cfg_section(body):
    """The heading text of a `// ... Name ... //` line (the closing // optional), or None.

    String operations for the same reason as _gcf_kv_match: the regex this replaces backtracked on a
    long run of dots or blanks. At least three dots each side, and at least one character between.
    """
    s = body.strip(" \t")
    if not s.startswith("//"):
        return None
    s = s[2:]
    if s.endswith("//"):
        s = s[:-2]
    s = s.strip(" \t")
    lead = len(s) - len(s.lstrip("."))
    trail = len(s) - len(s.rstrip("."))
    middle = s[lead:len(s) - trail]
    if lead < 3 or trail < 3 or not middle:
        return None
    return middle


def _gcf_cfg_line(body):
    """(key, value span in the line, style) when `body` sets one value, else None."""
    m = _GCF_CFG.match(body)
    if not m:
        return None
    if m.group(2) is not None:
        return m.group(1), m.span(2), "q"
    return m.group(1), m.span(3), "u"   # an unquoted value ends where a // comment starts


def _gcf_parse_cfg(text):
    """Fields of a Source / idTech cfg."""
    out, section, pending = [], "", []
    for off, body in _gcf_lines(text):
        sec = _gcf_cfg_section(body)
        if sec is not None:
            section, pending = sec.strip()[:_GCF_SECTION_MAX], []
            continue
        lead = body.lstrip(" \t")
        if lead.startswith("//"):
            said = lead.lstrip("/")   # the text after the run of slashes
            if not _gcf_is_decoration(said):
                pending.append(said.strip())
            continue
        got = _gcf_cfg_line(body)
        if got:
            key, (s, e), style = got
            out.append(_gcf_entry(key, off + s, off + e, body[s:e], section, pending, style))
        pending = []
    return out


# 7 Days to Die XML
_GCF_XML_BANNED = re.compile(r"<!DOCTYPE|<!ENTITY", re.I)
_GCF_XML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
_GCF_XML_PROP = re.compile(r"""<property\s+name\s*=\s*(?:"([^"<&]*)"|'([^'<&]*)')\s+"""
                           r"""value\s*=\s*(?:"([^"<\r\n]*)"|'([^'<\r\n]*)')\s*/>""")
_GCF_XML_ENTITY = re.compile(r"&(?:amp|lt|gt|quot|apos|#[0-9]{1,7}|#x[0-9A-Fa-f]{1,6});")


def _gcf_collapse(s):
    return " ".join(s.split())


def _gcf_own_line(text, pos):
    """True when only blanks stand between the start of `pos`'s line and `pos`."""
    line_start = max(text.rfind("\n", 0, pos), text.rfind("\r", 0, pos)) + 1
    return not text[line_start:pos].strip()


def _gcf_xml_value(raw):
    """The value an attribute's text stands for, or None when it uses an entity XML does not define."""
    if "&" in raw and _GCF_XML_ENTITY.sub("", raw).count("&"):
        return None
    return html.unescape(raw) if "&" in raw else raw


def _gcf_xml_before(text, comments, ci, last_end, pos, section):
    """Walk the comments before `pos`: (next comment index, the group, the comment right above or None)."""
    above = None
    while ci < len(comments) and comments[ci][0] < pos:
        s, e, words = comments[ci]
        ci += 1
        if s >= last_end and "<property" not in words and _gcf_own_line(text, s):
            section = words if len(words) <= _GCF_SECTION_MAX else section
            gap = text[e:pos]
            above = words if not gap.strip() and len(_GCF_EOL.findall(gap)) <= 1 else None
    return ci, section, above


def _gcf_xml_trail(text, comments, ci, end):
    """(the comment starting on the same line after `end`, or None; the next comment index)."""
    if ci < len(comments):
        gap = text[end:comments[ci][0]]
        if not gap.strip() and not _GCF_EOL.search(gap):
            return comments[ci], ci + 1
    return None, ci


def _gcf_xml_field(m, section, help_text):
    """The field for one <property> match, or None when its value uses an entity XML does not define."""
    quoted = 3 if m.group(3) is not None else 4
    value = _gcf_xml_value(m.group(quoted))
    if value is None:
        return None
    name = m.group(1) if m.group(1) is not None else m.group(2)
    return _gcf_entry(name, m.start(quoted), m.end(quoted), value, section, [help_text],
                      '"' if quoted == 3 else "'")


def _gcf_parse_xml(text):
    """Fields of a 7 Days to Die style XML file; None when it declares a DOCTYPE or an entity.

    A comment on a line of its own names the group of the properties after it, and is the help of
    the property right below it; a comment that starts on a property's own line is that property's
    help. A property inside a comment is not set, so it is no field.
    """
    if _GCF_XML_BANNED.search(text):
        return None
    comments = [(m.start(), m.end(), _gcf_collapse(m.group(1))) for m in _GCF_XML_COMMENT.finditer(text)]
    out, section, ci, last_end = [], "", 0, 0
    for m in _GCF_XML_PROP.finditer(text):
        ci, section, above = _gcf_xml_before(text, comments, ci, last_end, m.start(), section)
        if ci and comments[ci - 1][1] > m.start():
            continue
        trail, ci = _gcf_xml_trail(text, comments, ci, m.end())
        last_end = trail[1] if trail else m.end()
        field = _gcf_xml_field(m, section, trail[2] if trail else (above or ""))
        if field:
            out.append(field)
    return out


# JSON, with the place of every value it shows
_GCF_JSON_WS = re.compile(r"[ \t\n\r]*")


class _GcfJsonError(ValueError):
    """The text is not JSON this module can place values in."""


def _gcf_json_scalar(s, i):
    """(end, value, style) of the string, number, true, false or null at `i`."""
    if s[i] == '"':
        val, end = json.decoder.scanstring(s, i + 1)
        return end, val, "str"
    m = _GCF_JSON_NUMBER.match(s, i)
    if m:
        return m.end(), json.loads(m.group(0)), "num"
    for word, val in (("true", True), ("false", False), ("null", None)):
        if s.startswith(word, i):
            return i + len(word), val, ("null" if val is None else "bool")
    raise _GcfJsonError("bad value")


def _gcf_json_value(s, i, depth, sink, path):
    """Scan one JSON value at `i`: (end, value). Scalars at depth 1 and 2 are put in `sink`."""
    i = _GCF_JSON_WS.match(s, i).end()
    if i >= len(s):
        raise _GcfJsonError("end of text")
    if s[i] == "{":
        return _gcf_json_object(s, i, depth, sink, path)
    if s[i] == "[":
        return _gcf_json_array(s, i, depth, sink)
    end, val, style = _gcf_json_scalar(s, i)
    if path is not None and 1 <= depth <= 2:
        sink.append((path, i, end, val, style))
    return end, val


def _gcf_json_char(s, i, want, why):
    """The index after `want` at `i` (blanks skipped first); raises when it is not there."""
    i = _GCF_JSON_WS.match(s, i).end()
    if s[i:i + 1] != want:
        raise _GcfJsonError(why)
    return i + 1


def _gcf_json_more(s, i, close):
    """After a member or element: (index after the comma, True), or (index after `close`, False)."""
    i = _GCF_JSON_WS.match(s, i).end()
    if s[i:i + 1] == ",":
        return i + 1, True
    if s[i:i + 1] == close:
        return i + 1, False
    raise _GcfJsonError("bad separator")


def _gcf_json_object(s, i, depth, sink, path):
    obj, i = {}, _GCF_JSON_WS.match(s, i + 1).end()
    if s[i:i + 1] == "}":
        return i + 1, obj
    more = True
    while more:
        i = _gcf_json_char(s, i, '"', "bad key") - 1
        key, i = json.decoder.scanstring(s, i + 1)
        i = _gcf_json_char(s, i, ":", "no colon")
        child = (path + (key,)) if path is not None and depth < 2 else None
        i, obj[key] = _gcf_json_value(s, i, depth + 1, sink, child)
        i, more = _gcf_json_more(s, i, "}")
    return i, obj


def _gcf_json_array(s, i, depth, sink):
    arr, i = [], _GCF_JSON_WS.match(s, i + 1).end()
    if s[i:i + 1] == "]":
        return i + 1, arr
    more = True
    while more:
        i, val = _gcf_json_value(s, i, depth + 1, sink, None)
        arr.append(val)
        i, more = _gcf_json_more(s, i, "]")
    return i, arr


def _gcf_json_scan(text):
    """(document, [(path, start, end, value, style)]) for a JSON object; raises _GcfJsonError."""
    sink = []
    i = _GCF_JSON_WS.match(text, 0).end()
    if not text[i:i + 1] == "{":
        raise _GcfJsonError("not an object")
    end, doc = _gcf_json_value(text, i, 0, sink, ())
    if _GCF_JSON_WS.match(text, end).end() != len(text):
        raise _GcfJsonError("text after the object")
    return doc, sink


def _gcf_json_doc(text):
    """(document, sink) when the scanner reads exactly what the standard parser reads, else (None, None)."""
    try:
        doc, sink = _gcf_json_scan(text)
        if json.loads(text, parse_constant=_gcf_no_constant) != doc:
            return None, None
    except (ValueError, RecursionError):
        return None, None
    return doc, sink


def _gcf_json_helps(doc, sink):
    """{path of a key: its help}, from `_comment_<key>` members (a string, or a list of strings)."""
    helps = {path[:-1] + (path[-1][len("_comment_"):],): val for path, _s, _e, val, _style in sink
             if path[-1].startswith("_comment_") and isinstance(val, str)}
    helps.update(_gcf_json_comment_lists(doc))
    return helps


def _gcf_json_shown(text, start, end, val, style):
    """A JSON value as its field shows it: a string decoded, a number as written, null empty."""
    if val is None:
        return ""
    if style == "bool":
        return json.dumps(val)
    return text[start:end] if style == "num" else val


def _gcf_parse_json(text):
    """Fields of a JSON object file; None when it is not one this module can place values in."""
    doc, sink = _gcf_json_doc(text)
    if doc is None:
        return None
    helps = _gcf_json_helps(doc, sink)
    return [_gcf_entry(path[-1], start, end, _gcf_json_shown(text, start, end, val, style),
                       path[0] if len(path) == 2 else "", [helps.get(path, "")], style)
            for path, start, end, val, style in sink if not path[-1].startswith("_comment")]


def _gcf_no_constant(name):
    raise ValueError("not JSON: %s" % name)


def _gcf_json_comment_lists(doc):
    """(path, text) for a `_comment_<key>` that is a list of strings, at the top or one level down."""
    scopes = [((), doc)] + [((k,), v) for k, v in doc.items() if isinstance(v, dict)]
    return [(scope + (k[len("_comment_"):],), "\n".join(v)) for scope, obj in scopes for k, v in obj.items()
            if k.startswith("_comment_") and isinstance(v, list) and all(isinstance(x, str) for x in v)]


# ── which format ─────────────────────────────────────────────────────────────────────────────────
def _gcf_ext(rel):
    name = (rel or "").rsplit("/", 1)[-1].lower()
    return name[name.rfind("."):] if "." in name else ""


def _gcf_claims(text):
    """(lines a cfg reading takes, lines a key=value reading takes, lines that are neither blank nor comment)."""
    cfg = kv = total = 0
    for _off, body in _gcf_lines(text):
        stripped = body.strip()
        if not stripped or stripped.startswith(("//", "#", ";")):
            continue
        total += 1
        if _gcf_cfg_line(body):
            cfg += 1
        m = _gcf_kv_match(body)
        if m and not re.search(r"\s", m.group(1)):
            kv += 1
    return cfg, kv, total


def _gcf_pick(content):
    """cfg, kv or None for a .cfg/.txt/.conf file, by what two lines in three look like.

    A page of prose has lines that look like `word value`, so a bare majority is not enough.
    """
    cfg, kv, total = _gcf_claims(content)
    if not total:
        return None
    if cfg >= kv and cfg * 3 >= total * 2:
        return "cfg"
    return "kv" if kv > cfg and kv * 3 >= total * 2 else None


def detect(rel, content):
    """The format of the file at `rel` holding `content`: kv, cfg, xml or json, or None for the raw editor only."""
    if not isinstance(content, str) or "\x00" in content:
        return None
    choices = _GCF_EXT_FORMATS.get(_gcf_ext(rel)) or (None,)
    return choices[0] if len(choices) == 1 else _gcf_pick(content)


def parse(rel, content):
    """(format, fields) for the file, or (None, []) when it has no form view."""
    fmt = detect(rel, content)
    if fmt == "kv":
        fields = _gcf_parse_kv(content, _gcf_ext(rel) == ".properties")
    elif fmt == "cfg":
        fields = _gcf_parse_cfg(content)
    elif fmt == "xml":
        fields = _gcf_parse_xml(content)
    elif fmt == "json":
        fields = _gcf_parse_json(content)
    else:
        fields = None
    if not fields or len(fields) > MAX_FIELDS:
        return None, []
    for f in fields:
        _gcf_classify(fmt, f)
    return fmt, fields


def _gcf_kind(fmt, f):
    """(kind, switch-on spelling, switch-off spelling) for a field: bool, number or text."""
    v, style = f["value"], f["style"]
    if fmt == "json":
        return {"bool": ("bool", "true", "false"), "num": ("number", None, None)}.get(style, ("text", None, None))
    if v.lower() in _GCF_BOOL_WORDS:
        return "bool", _gcf_spell(v, "true"), _gcf_spell(v, "false")
    if v in ("0", "1") and _GCF_TOGGLE_HELP.search(f["help"]):
        return "bool", "1", "0"
    return ("number", None, None) if _GCF_NUMBER.fullmatch(v) else ("text", None, None)


def _gcf_classify(fmt, f):
    """Set the field's kind, its switch spellings, and whether it is secret (a switch never is)."""
    f["kind"], f["on"], f["off"] = _gcf_kind(fmt, f)
    f["secret"] = f["kind"] != "bool" and is_secret_key(f["key"])


def _gcf_spell(like, word):
    """`word` (true/false) written the way `like` is: TRUE, True or true."""
    if like.isupper():
        return word.upper()
    return word.capitalize() if like[:1].isupper() else word


def build(rel, content):
    """The form the page draws, or None when the file has only the raw editor.

    {"format", "hash", "groups": [{"name", "fields": [{"id", "key", "value", "kind", "help",
    "secret", "on", "off"}]}]}. A secret field's value is sent like any other: the raw editor beside
    the form already shows the whole file, secrets included, to the same people (the Settings tab's
    permission). The page puts it in a password input's value property, never in the page's HTML.
    """
    fmt, fields = parse(rel, content)
    if fmt is None:
        return None
    groups, by_name = [], {}
    for i, f in enumerate(fields):
        if f["section"] not in by_name:
            by_name[f["section"]] = {"name": f["section"], "fields": []}
            groups.append(by_name[f["section"]])
        by_name[f["section"]]["fields"].append({k: f[k] for k in ("key", "value", "kind", "help", "secret", "on",
                                                                  "off")} | {"id": i})
    return {"format": fmt, "hash": content_hash(content), "groups": groups}


# ── writing ──────────────────────────────────────────────────────────────────────────────────────
def _gcf_bad_chars(value):
    return any(unicodedata.category(c) in ("Cc", "Zl", "Zp", "Cs") for c in value)


def _gcf_check(fmt, ext, f, value):
    """None when `value` may be written to field `f`, else why not."""
    if _gcf_bad_chars(value):
        return BAD_CHARS
    if len(value) > VALUE_MAX:
        return TOO_LONG
    why = _gcf_check_kind(fmt, f, value)
    if why or fmt not in ("kv", "cfg"):
        return why
    return _gcf_check_kv(ext, f, value) if fmt == "kv" else _gcf_check_cfg(f, value)


def _gcf_check_kind(fmt, f, value):
    """A switch takes only its two spellings, a number field a number."""
    if f["kind"] == "bool" and value not in (f["on"], f["off"]):
        return i18n.Sentence(BAD_BOOL, key=f["key"], on=f["on"], off=f["off"])
    number = _GCF_JSON_NUMBER if fmt == "json" else _GCF_NUMBER
    if f["kind"] == "number" and not number.fullmatch(value):
        return i18n.Sentence(BAD_NUMBER, key=f["key"])
    return None


def _gcf_check_kv(ext, f, value):
    """key=value: the reader trims the value, and .properties joins a line ending in a backslash."""
    if value != value.strip():
        return i18n.Sentence(EDGE_SPACE, key=f["key"])
    if ext == ".properties" and _gcf_odd_backslashes(value):
        return i18n.Sentence(TRAIL_BACKSLASH, key=f["key"])
    return None


def _gcf_check_cfg(f, value):
    key = f["key"]
    if '"' in value:
        return i18n.Sentence(CFG_QUOTE, key=key)
    if f["style"] == "u" and (";" in value or "//" in value):
        return i18n.Sentence(CFG_BREAKS, key=key)
    return None


def _gcf_encode(fmt, f, value):
    """The text written in place of field `f`'s value."""
    if fmt == "cfg" and f["style"] == "u" and (not value or re.search(r"\s", value)):
        return '"%s"' % value   # an unquoted value that is empty or holds a blank needs its quotes
    if fmt == "xml":
        out = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return out.replace('"', "&quot;") if f["style"] == '"' else out.replace("'", "&apos;")
    if fmt == "json" and f["style"] in ("str", "null"):
        return json.dumps(value, ensure_ascii=False)
    return value


def _gcf_same_fields(old, new, changed):
    """True when `new` holds the same fields as `old`, the changed ones with their new values."""
    if len(old) != len(new):
        return False
    for i, (a, b) in enumerate(zip(old, new)):
        if a["key"] != b["key"] or a["section"] != b["section"]:
            return False
        if b["value"] != changed.get(i, a["value"]):
            return False
    return True


def _gcf_todo(fmt, ext, fields, changes):
    """({field id: new value} for the values that change, None), or ({}, why) when one is refused."""
    if not isinstance(changes, dict) or len(changes) > MAX_FIELDS:
        return {}, BAD_CHANGES
    todo = {}
    for raw_id, value in changes.items():
        fid = _gcf_field_id(raw_id, len(fields))
        if fid is None:
            return {}, NO_FIELD
        if not isinstance(value, str):
            return {}, BAD_CHANGES
        why = None if value == fields[fid]["value"] else _gcf_check(fmt, ext, fields[fid], value)
        if why:
            return {}, why
        if value != fields[fid]["value"]:
            todo[fid] = value
    return todo, None


def _gcf_splice(fmt, content, fields, todo):
    """`content` with each changed field's value text replaced, last first so earlier offsets hold."""
    for fid in sorted(todo, key=lambda k: fields[k]["start"], reverse=True):
        f = fields[fid]
        content = content[:f["start"]] + _gcf_encode(fmt, f, todo[fid]) + content[f["end"]:]
    return content


def apply(rel, content, expected_hash, changes):
    """(new content, [(field, old value, new value)], None), or (None, [], why) when refused.

    `changes` maps a field's id (from build) to its new value as text. A value equal to the old one
    is no change. Nothing changed answers the content as it was, with an empty list.
    """
    if not isinstance(expected_hash, str) or content_hash(content) != expected_hash:
        return None, [], CHANGED
    fmt, fields = parse(rel, content)
    if fmt is None:
        return None, [], NO_FORM
    todo, why = _gcf_todo(fmt, _gcf_ext(rel), fields, changes)
    if why or not todo:
        return (None, [], why) if why else (content, [], None)
    new = _gcf_splice(fmt, content, fields, todo)
    fmt2, again = parse(rel, new)
    if fmt2 != fmt or not _gcf_same_fields(fields, again, todo):
        return None, [], UNSAFE
    return new, [(fields[k], fields[k]["value"], todo[k]) for k in sorted(todo)], None


def _gcf_field_id(raw_id, count):
    """A field id from the request (an int, or its decimal text) if it names a field, else None."""
    if isinstance(raw_id, bool):
        return None
    if isinstance(raw_id, str) and re.fullmatch(r"0|[1-9][0-9]{0,5}", raw_id):
        raw_id = int(raw_id)
    return raw_id if isinstance(raw_id, int) and 0 <= raw_id < count else None


def audit_detail(changed, limit=60):
    """`key: old -> new` per changed field for the audit row; a secret field's values never appear."""
    parts = []
    for f, old, new in changed:
        if f["secret"]:
            parts.append("%s: changed (hidden)" % f["key"])
        else:
            parts.append("%s: %s -> %s" % (f["key"], _gcf_clip(old, limit), _gcf_clip(new, limit)))
    return "; ".join(parts)


def _gcf_clip(s, limit):
    return s if len(s) <= limit else s[:limit - 1] + "…"
